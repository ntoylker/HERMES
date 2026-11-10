"""llm_client.py: one LLM client for the thesis pipeline, unchanged on your PC and on Colab.

    On your PC  -> LM Studio at http://localhost:1234/v1 (the default)
    On Colab    -> Ollama at the same URL, started by qwen38_colab_server.ipynb,
                   which also sets the environment variables below

Standard library only. pydantic is needed only if you use pydantic_validator().

Configuration (environment variables)
    LLM_BASE_URL        default "http://localhost:1234/v1"
    LLM_MODEL           model name. Colab: "qwen38-unc" (set by the notebook). PC: your LM Studio model id.
                        If unset and the server offers exactly one model, that one is used.
    LLM_API_KEY         default "local" (both servers ignore it)
    LLM_CONTEXT_LENGTH  the server's context window; turns on the truncation checks (set by the notebook)
    LLM_MAX_TOKENS      default output budget (thinking + answer). Default: min(49152, context/2), or 16384
    LLM_TIMEOUT_S       how long to wait for the server, in seconds. Default 7200: one attempt can take
                        ~30 min on an L4, and the OpenAI SDK's default (600 s, then 2 silent retries)
                        would abort and restart every long call
    LLM_STREAM          "1" (default): stream, so progress is visible and the time to first token is logged
    LLM_PROGRESS_S      seconds between progress lines while streaming. Default 60; 0 turns them off
    LLM_LOG_PATH        JSONL file that gets one line per call and per validation. Default "llm_calls.jsonl"
    LLM_RUN_CONFIG      path to the notebook's run_config.json; its GPU, quant and Ollama version go into
                        every log line

Typical use
    from llm_client import generate_with_retries, pydantic_validator, checkpoint

    def make_plan():
        return generate_with_retries(SYSTEM_PROMPT, task_prompt,
                                     validate=pydantic_validator(CodePlan),
                                     schema=CodePlan.model_json_schema(), tag=task_id)

    plan_json = checkpoint(f"{out_dir}/{task_id}.json", make_plan)   # skips tasks that are already done

Rules this module enforces
    - Retries are "smart": system + original task + the LAST failed answer + its error. The context
      stays constant, and the model's thinking is never sent back.
    - The system prompt and task are sent byte-identical on every attempt, so the server can reuse
      its cached prompt prefix and retries start faster.
    - Every call is logged with prompt/completion tokens, finish reason, timings and warnings for a
      probably truncated prompt, a cut-off answer, or an empty answer.

Quick check against whatever server LLM_BASE_URL points to:   python llm_client.py
"""
from __future__ import annotations

import datetime as _dt
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

__all__ = [
    "LLMError", "RetriesExhausted", "LLMResult", "settings", "resolve_model", "call",
    "split_reasoning", "retry_messages", "generate_with_retries", "pydantic_validator", "checkpoint",
]

CHARS_PER_TOKEN = 3.5   # rough, for warnings only. The notebook's long-context test measures the real value
RUN_CONFIG_KEYS = ("gpu", "quant", "gguf_file", "hf_repo", "ollama_version", "context_length", "kv_cache")
RETRY_INSTRUCTION = ("Your previous output failed validation:\n{error}\n"
                     "Return the FULL corrected output, not just the changes.")


class LLMError(RuntimeError):
    """The server could not be reached or returned an error. Not a mistake by the model."""


class RetriesExhausted(RuntimeError):
    def __init__(self, tag: str, error: str, last_output: str, attempts: int):
        super().__init__(f"{tag}: still invalid after {attempts} attempts. Last error: {error[:500]}")
        self.tag, self.error, self.last_output, self.attempts = tag, error, last_output, attempts


@dataclass
class LLMResult:
    content: str      # the answer only
    reasoning: str    # the thinking. Log it if you like, but never send it back to the model
    record: dict      # what was written to the log

    def __iter__(self):   # allows: content, reasoning, record = call(...)
        return iter((self.content, self.reasoning, self.record))


# ---------------------------------------------------------------- configuration

def _env_int(name: str) -> int | None:
    value = os.environ.get(name, "").strip()
    return int(value) if value else None


def settings() -> dict:
    """Current configuration. Read on every call, so changing os.environ takes effect immediately."""
    return {
        "base_url": os.environ.get("LLM_BASE_URL", "http://localhost:1234/v1").strip().rstrip("/"),
        "model": os.environ.get("LLM_MODEL", "").strip(),
        "api_key": os.environ.get("LLM_API_KEY", "local"),
        "context": _env_int("LLM_CONTEXT_LENGTH"),
        "max_tokens": _env_int("LLM_MAX_TOKENS"),
        "timeout": float(os.environ.get("LLM_TIMEOUT_S", "7200")),
        "stream": os.environ.get("LLM_STREAM", "1").strip() != "0",
        "progress_s": float(os.environ.get("LLM_PROGRESS_S", "60")),
        "log_path": os.environ.get("LLM_LOG_PATH", "llm_calls.jsonl"),
        "run_config": os.environ.get("LLM_RUN_CONFIG", ""),
    }


def _say(message: str) -> None:
    print(message, file=sys.stderr, flush=True)


def _run_info(path: str) -> dict:
    if not path:
        return {}
    try:
        with open(path, encoding="utf-8") as f:
            cfg = json.load(f)
    except (OSError, ValueError):
        return {}
    return {k: cfg[k] for k in RUN_CONFIG_KEYS if k in cfg}


def _log(path: str, record: dict) -> None:
    if not path:
        return
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


def _now() -> str:
    return _dt.datetime.now().isoformat(timespec="seconds")


# ---------------------------------------------------------------- HTTP

def _open(method: str, url: str, api_key: str, timeout: float, payload: dict | None = None):
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(url, data=data, method=method, headers={
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "Authorization": f"Bearer {api_key}",
    })
    host = urllib.parse.urlsplit(url).hostname or ""
    # A local server must never go through a proxy configured in the environment
    handlers = [urllib.request.ProxyHandler({})] if host in ("localhost", "127.0.0.1", "::1") else []
    try:
        return urllib.request.build_opener(*handlers).open(request, timeout=timeout)
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", "replace")[:2000]
        raise LLMError(f"HTTP {e.code} from {url}: {body}") from None
    except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
        reason = getattr(e, "reason", e)
        raise LLMError(f"Cannot reach {url} ({reason}). Is the model server running, "
                       f"and is LLM_BASE_URL right?") from None


_MODEL_CACHE: dict[str, str] = {}


def resolve_model(cfg: dict | None = None) -> str:
    cfg = cfg or settings()
    if cfg["model"]:
        return cfg["model"]
    base = cfg["base_url"]
    if base not in _MODEL_CACHE:
        with _open("GET", f"{base}/models", cfg["api_key"], 30) as response:
            ids = [m.get("id") for m in json.load(response).get("data", [])]
        if len(ids) != 1:
            raise LLMError(f"Set LLM_MODEL. The server at {base} offers {len(ids)} models: {ids}")
        _MODEL_CACHE[base] = ids[0]
    return _MODEL_CACHE[base]


def _text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):   # OpenAI "content parts"
        return "".join(p.get("text", "") for p in content if isinstance(p, dict))
    return ""


def split_reasoning(content: str, reasoning: str = "") -> tuple[str, str]:
    """Moves <think>...</think> text out of the answer.

    Ollama and LM Studio (with its "separate reasoning" setting) already return the thinking in its own
    field. Without that setting, LM Studio leaves it in the content as <think>...</think>, or only the
    closing tag when the chat template opens the block itself.
    """
    stripped = content.lstrip()
    if "</think>" in content:
        before, _, after = content.partition("</think>")
        before = before.replace("<think>", "", 1).strip()
        return after.lstrip(), "\n".join(x for x in (reasoning, before) if x)
    if stripped.startswith("<think>"):   # never closed: cut off while thinking
        return "", "\n".join(x for x in (reasoning, stripped[len("<think>"):].strip()) if x)
    return content, reasoning


def _read_stream(response, cfg: dict, tag: str, t0: float):
    content, reasoning = [], []
    finish, usage, first_token_s = None, None, None
    n_content = n_reasoning = 0
    beat = cfg["progress_s"]
    next_beat = t0 + beat if beat > 0 else float("inf")
    try:
        for raw in response:
            line = raw.decode("utf-8", "replace").strip()
            if not line.startswith("data:"):
                continue
            data = line[5:].strip()
            if data == "[DONE]":
                break
            try:
                chunk = json.loads(data)
            except ValueError:
                raise LLMError(f"Unreadable data from the server: {data[:300]}") from None
            if chunk.get("error"):
                raise LLMError(f"Server error during generation: {chunk['error']}")
            if chunk.get("usage"):
                usage = chunk["usage"]
            for choice in chunk.get("choices") or []:
                delta = choice.get("delta") or {}
                r = delta.get("reasoning") or delta.get("reasoning_content") or ""
                c = delta.get("content") or ""
                if (r or c) and first_token_s is None:
                    first_token_s = round(time.time() - t0, 1)
                if r:
                    reasoning.append(r)
                    n_reasoning += len(r)
                if c:
                    content.append(c)
                    n_content += len(c)
                if choice.get("finish_reason"):
                    finish = choice["finish_reason"]
            now = time.time()
            if now >= next_beat:
                _say(f"[llm] {tag}: {(now - t0) / 60:.1f} min | thinking {n_reasoning:,} chars "
                     f"| answer {n_content:,} chars")
                next_beat = now + beat
    except TimeoutError:
        raise LLMError(f"No data from the server for {cfg['timeout']:.0f} s (LLM_TIMEOUT_S)") from None
    return "".join(content), "".join(reasoning), finish, usage, first_token_s


# ---------------------------------------------------------------- one call

def call(messages: list[dict], schema: dict | None = None, *, max_tokens: int | None = None,
         temperature: float | None = 1.0, top_p: float | None = 0.95, tag: str = "",
         stream: bool | None = None, extra: dict | None = None, schema_name: str = "output") -> LLMResult:
    """One chat completion. Returns LLMResult(content, reasoning, record); every call is logged.

    schema: a JSON schema (e.g. MyModel.model_json_schema()). The server then constrains the answer to it.
    temperature/top_p: Qwen's thinking-mode values by default; None leaves them to the server.
    extra: more request fields, e.g. {"seed": 1}.
    Raises LLMError if the server can't be reached or reports an error.
    """
    cfg = settings()
    model = resolve_model(cfg)
    ctx = cfg["context"]
    if max_tokens is None:
        max_tokens = cfg["max_tokens"] or (min(49152, ctx // 2) if ctx else 16384)
    stream = cfg["stream"] if stream is None else stream
    tag = tag or "call"

    est_prompt = round(sum(len(_text(m.get("content"))) for m in messages) / CHARS_PER_TOKEN)
    if ctx and est_prompt + max_tokens > ctx:
        _say(f"WARNING [{tag}]: estimated prompt (~{est_prompt:,} tokens) + max_tokens ({max_tokens:,}) "
             f"> context ({ctx:,}). The start of the prompt may be dropped, or the answer cut off.")

    payload: dict[str, Any] = {"model": model, "messages": messages, "max_tokens": max_tokens,
                               "stream": stream}
    if temperature is not None:
        payload["temperature"] = temperature
    if top_p is not None:
        payload["top_p"] = top_p
    if schema is not None:
        payload["response_format"] = {"type": "json_schema",
                                      "json_schema": {"name": schema_name, "strict": True, "schema": schema}}
    if stream:
        payload["stream_options"] = {"include_usage": True}
    if extra:
        payload.update(extra)

    url = f"{cfg['base_url']}/chat/completions"
    if stream and cfg["progress_s"] > 0:
        _say(f"[llm] {tag}: sent ~{est_prompt:,} prompt tokens to {model}")
    t0 = time.time()
    with _open("POST", url, cfg["api_key"], cfg["timeout"], payload) as response:
        if stream:
            content, reasoning, finish, usage, first_token_s = _read_stream(response, cfg, tag, t0)
        else:
            try:
                body = json.load(response)
            except TimeoutError:
                raise LLMError(f"No answer from the server within {cfg['timeout']:.0f} s "
                               f"(LLM_TIMEOUT_S)") from None
            if body.get("error"):
                raise LLMError(f"Server error: {body['error']}")
            choice = (body.get("choices") or [{}])[0]
            message = choice.get("message") or {}
            content = message.get("content") or ""
            reasoning = message.get("reasoning") or message.get("reasoning_content") or ""
            finish, usage, first_token_s = choice.get("finish_reason"), body.get("usage"), None
    seconds = round(time.time() - t0, 1)
    content, reasoning = split_reasoning(content, reasoning)

    usage = usage or {}
    prompt_tokens, completion_tokens = usage.get("prompt_tokens"), usage.get("completion_tokens")
    record = {
        "type": "call", "time": _now(), "tag": tag, "base_url": cfg["base_url"], "model": model,
        "seconds": seconds, "first_token_s": first_token_s,
        "prompt_tokens": prompt_tokens, "completion_tokens": completion_tokens,
        "est_prompt_tokens": est_prompt, "finish_reason": finish, "max_tokens": max_tokens,
        "context": ctx, "temperature": temperature, "top_p": top_p, "schema": schema is not None,
        "stream": stream, "reasoning_chars": len(reasoning), "content_chars": len(content),
        "warnings": [], **_run_info(cfg["run_config"]),
    }
    if completion_tokens and seconds:
        record["tokens_per_s"] = round(completion_tokens / max(seconds - (first_token_s or 0), 0.1), 1)
    if ctx and prompt_tokens and prompt_tokens >= 0.95 * ctx:
        record["warnings"].append("PROMPT PROBABLY TRUNCATED: prompt_tokens is close to the context size")
    if finish == "length":
        record["warnings"].append("OUTPUT CUT OFF (finish_reason=length): raise max_tokens or shorten the prompt")
    if not content.strip():
        record["warnings"].append("EMPTY ANSWER: the thinking may have used the whole token budget")
    if prompt_tokens is None:
        record["warnings"].append("NO TOKEN COUNTS from the server: truncation can't be checked")
    _log(cfg["log_path"], record)
    for warning in record["warnings"]:
        _say(f"WARNING [{tag}]: {warning}")
    return LLMResult(content, reasoning, record)


# ---------------------------------------------------------------- retries, validation, checkpoints

def retry_messages(system: str | None, task: str, last_output: str, error: str) -> list[dict]:
    """The smart-retry message list: original task + LAST answer (content only) + its error."""
    head = [{"role": "system", "content": system}] if system else []
    return head + [{"role": "user", "content": task},
                   {"role": "assistant", "content": last_output},
                   {"role": "user", "content": RETRY_INSTRUCTION.format(error=error)}]


def generate_with_retries(system: str | None, task: str, validate: Callable[[str], tuple[bool, str]],
                          schema: dict | None = None, *, max_retries: int = 5, tag: str = "task",
                          **call_kwargs) -> str:
    """Calls the model until validate(content) -> (True, "") or the retries run out.

    validate gets the answer text and returns (ok, error_message). The error message is what the
    model sees on the next attempt, so make it specific (a validation error, failing test output...).
    Returns the first valid answer; raises RetriesExhausted otherwise.
    """
    first = ([{"role": "system", "content": system}] if system else []) + [{"role": "user", "content": task}]
    messages, content, error = first, "", ""
    log_path = settings()["log_path"]
    for attempt in range(max_retries + 1):
        result = call(messages, schema, tag=f"{tag}#{attempt}", **call_kwargs)
        content = result.content
        if content.strip():
            try:
                ok, error = validate(content)
            except Exception as e:   # a crashing validator counts as a failed validation
                ok, error = False, f"{type(e).__name__}: {e}"
        else:
            ok, error = False, "empty answer"
        _log(log_path, {"type": "validation", "time": _now(), "tag": f"{tag}#{attempt}", "ok": ok,
                        "error": (error or "")[:2000]})
        rec = result.record
        _say(f"[llm] {tag} attempt {attempt}: {'OK' if ok else 'FAILED'} | prompt {rec['prompt_tokens']} "
             f"| output {rec['completion_tokens']} | {rec['seconds']} s")
        if ok:
            return content
        # An empty answer has nothing to correct: send the original task again for a fresh sample
        messages = retry_messages(system, task, content, error) if content.strip() else first
    raise RetriesExhausted(tag, error, content, max_retries + 1)


def pydantic_validator(model_cls) -> Callable[[str], tuple[bool, str]]:
    """validate() for generate_with_retries: the answer must parse as model_cls (a pydantic model)."""
    def validate(text: str) -> tuple[bool, str]:
        try:
            model_cls.model_validate_json(text)
            return True, ""
        except Exception as e:
            return False, str(e)[:4000]
    return validate


def checkpoint(path: str | os.PathLike, produce: Callable[[], str]) -> str:
    """Returns the result saved at `path` if it exists. Otherwise runs produce(), saves the text, returns it.

    Save under THESIS_OUT_DIR (set by the Colab notebook, on Drive), so a disconnect costs at most the
    task that was running, and a re-run skips everything already done.
    """
    p = Path(path)
    if p.exists():
        return p.read_text(encoding="utf-8")
    text = produce()
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_name(p.name + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, p)   # a half-written file never looks finished
    return text


# ---------------------------------------------------------------- self-test

def _selftest() -> int:
    cfg = settings()
    print(f"Server: {cfg['base_url']} | context: {cfg['context'] or 'unknown'} | stream: {cfg['stream']} "
          f"| timeout: {cfg['timeout']:.0f} s | log: {cfg['log_path']}")
    print(f"Model: {resolve_model(cfg)}")
    print("1/2 plain answer (thinking models think first; on an L4 this can take a minute) ...")
    r = call([{"role": "user", "content": "Reply with the single word OK."}], max_tokens=4096, tag="selftest")
    print(f"    answer {r.content.strip()[:80]!r} | thinking {len(r.reasoning):,} chars | "
          f"prompt {r.record['prompt_tokens']} | output {r.record['completion_tokens']} | "
          f"{r.record['seconds']} s | finish {r.record['finish_reason']}")
    print("2/2 JSON-schema answer ...")
    schema = {"type": "object", "properties": {"ok": {"type": "boolean"}, "word": {"type": "string"}},
              "required": ["ok", "word"], "additionalProperties": False}
    r = call([{"role": "user", "content": 'Return JSON with ok=true and word="hello".'}], schema,
             max_tokens=4096, tag="selftest-schema")
    try:
        data = json.loads(r.content)
        passed = isinstance(data, dict) and isinstance(data.get("ok"), bool) and isinstance(data.get("word"), str)
    except ValueError:
        passed = False
    print(f"    answer {r.content.strip()[:80]!r} -> {'PASS' if passed else 'FAIL: not valid for the schema'}")
    return 0 if passed else 1


if __name__ == "__main__":
    try:
        sys.exit(_selftest())
    except LLMError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(2)
