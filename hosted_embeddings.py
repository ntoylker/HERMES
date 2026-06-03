import os
import time
from dataclasses import dataclass

import requests


class EmbeddingError(RuntimeError):
    pass


@dataclass(frozen=True)
class EmbeddingConfig:
    provider: str
    model: str | None = None
    base_url: str | None = None
    api_key: str | None = None

    # Azure-only
    azure_endpoint: str | None = None
    azure_deployment: str | None = None
    azure_api_version: str | None = None


def _env(name: str) -> str | None:
    value = os.getenv(name)
    return value if value and value.strip() else None


def load_embedding_config(provider: str | None = None, model: str | None = None) -> EmbeddingConfig:
    explicit = (provider or _env("EMBED_PROVIDER"))
    if explicit and explicit.strip():
        provider = explicit.strip().lower()
    else:
        # Auto-detect based on which API key is present.
        # Priority: Google AI Studio -> Azure OpenAI -> OpenAI.
        if _env("GOOGLE_API_KEY") or _env("GEMINI_API_KEY"):
            provider = "google_ai_studio"
        elif _env("AZURE_OPENAI_API_KEY") and _env("AZURE_OPENAI_ENDPOINT"):
            provider = "azure_openai"
        elif _env("OPENAI_API_KEY"):
            provider = "openai"
        else:
            provider = "openai"

    if provider in {"openai", "openai_compatible"}:
        api_key = _env("OPENAI_API_KEY")
        base_url = (_env("OPENAI_BASE_URL") or "https://api.openai.com/v1").rstrip("/")
        model = model or _env("OPENAI_EMBED_MODEL") or "text-embedding-3-small"
        return EmbeddingConfig(provider=provider, model=model, base_url=base_url, api_key=api_key)

    if provider in {"azure", "azure_openai"}:
        endpoint = _env("AZURE_OPENAI_ENDPOINT")
        api_key = _env("AZURE_OPENAI_API_KEY")
        deployment = model or _env("AZURE_OPENAI_EMBED_DEPLOYMENT")
        api_version = _env("AZURE_OPENAI_API_VERSION") or "2024-02-15-preview"
        return EmbeddingConfig(
            provider=provider,
            model=None,
            azure_endpoint=endpoint,
            azure_deployment=deployment,
            azure_api_version=api_version,
            api_key=api_key,
        )

    if provider in {"google_ai_studio", "google-aistudio", "gemini", "google"}:
        # Per Gemini API docs, GEMINI_API_KEY or GOOGLE_API_KEY can be used.
        api_key = _env("GOOGLE_API_KEY") or _env("GEMINI_API_KEY")
        base_url = (_env("GEMINI_BASE_URL") or "https://generativelanguage.googleapis.com/v1beta").rstrip("/")
        model = model or _env("GEMINI_EMBED_MODEL") or _env("GOOGLE_EMBED_MODEL") or "gemini-embedding-2"
        return EmbeddingConfig(provider="google_ai_studio", model=model, base_url=base_url, api_key=api_key)

    raise EmbeddingError(f"Unknown embedding provider: {provider}")


class EmbeddingClient:
    def embed_texts(self, texts: list[str]) -> list[list[float]]:
        raise NotImplementedError


class OpenAIEmbeddingClient(EmbeddingClient):
    def __init__(self, *, api_key: str, base_url: str, model: str, timeout_s: int = 60):
        self._api_key = api_key
        self._base_url = base_url.rstrip("/")
        self._model = model
        self._timeout_s = timeout_s

    def embed_texts(self, texts: list[str]) -> list[list[float]]:
        if not self._api_key:
            raise EmbeddingError(
                "Missing OPENAI_API_KEY. Set OPENAI_API_KEY, or set EMBED_PROVIDER/--provider "
                "to google_ai_studio and provide GOOGLE_API_KEY (or GEMINI_API_KEY), "
                "or use --lexical-only for no-embeddings mode."
            )
        if not texts:
            return []

        url = f"{self._base_url}/embeddings"
        headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
        }
        payload = {"model": self._model, "input": texts}

        data = _request_with_retries(url, headers=headers, payload=payload, timeout_s=self._timeout_s)
        items = data.get("data") or []
        if len(items) != len(texts):
            raise EmbeddingError(f"Embedding API returned {len(items)} items for {len(texts)} inputs")

        # Respect returned indices.
        out: list[list[float]] = [None] * len(texts)  # type: ignore[assignment]
        for item in items:
            idx = item.get("index")
            emb = item.get("embedding")
            if idx is None or emb is None:
                raise EmbeddingError("Malformed embedding response: missing index/embedding")
            out[int(idx)] = emb
        if any(v is None for v in out):
            raise EmbeddingError("Malformed embedding response: missing one or more embeddings")
        return out  # type: ignore[return-value]


class AzureOpenAIEmbeddingClient(EmbeddingClient):
    def __init__(
        self,
        *,
        api_key: str,
        endpoint: str,
        deployment: str,
        api_version: str,
        timeout_s: int = 60,
    ):
        self._api_key = api_key
        self._endpoint = endpoint.rstrip("/")
        self._deployment = deployment
        self._api_version = api_version
        self._timeout_s = timeout_s

    def embed_texts(self, texts: list[str]) -> list[list[float]]:
        if not self._api_key:
            raise EmbeddingError("Missing AZURE_OPENAI_API_KEY")
        if not self._endpoint:
            raise EmbeddingError("Missing AZURE_OPENAI_ENDPOINT")
        if not self._deployment:
            raise EmbeddingError("Missing AZURE_OPENAI_EMBED_DEPLOYMENT")
        if not texts:
            return []

        url = (
            f"{self._endpoint}/openai/deployments/{self._deployment}/embeddings"
            f"?api-version={self._api_version}"
        )
        headers = {
            "api-key": self._api_key,
            "Content-Type": "application/json",
        }
        payload = {"input": texts}

        data = _request_with_retries(url, headers=headers, payload=payload, timeout_s=self._timeout_s)
        items = data.get("data") or []
        if len(items) != len(texts):
            raise EmbeddingError(f"Embedding API returned {len(items)} items for {len(texts)} inputs")

        out: list[list[float]] = [None] * len(texts)  # type: ignore[assignment]
        for item in items:
            idx = item.get("index")
            emb = item.get("embedding")
            if idx is None or emb is None:
                raise EmbeddingError("Malformed embedding response: missing index/embedding")
            out[int(idx)] = emb
        if any(v is None for v in out):
            raise EmbeddingError("Malformed embedding response: missing one or more embeddings")
        return out  # type: ignore[return-value]


class GoogleAIStudioEmbeddingClient(EmbeddingClient):
    def __init__(self, *, api_key: str, base_url: str, model: str, timeout_s: int = 60):
        self._api_key = api_key
        self._base_url = base_url.rstrip("/")
        self._model = model
        self._timeout_s = timeout_s

    def _model_resource_name(self) -> str:
        m = (self._model or "").strip()
        if not m:
            return "models/gemini-embedding-2"
        return m if m.startswith("models/") else f"models/{m}"

    def embed_texts(self, texts: list[str]) -> list[list[float]]:
        if not self._api_key:
            raise EmbeddingError("Missing GOOGLE_API_KEY (or GEMINI_API_KEY)")
        if not texts:
            return []

        model_name = self._model_resource_name()

        # Gemini Embedding 2 doesn't support task_type; it recommends task instructions in-text.
        # We keep a very small, retrieval-oriented formatting using the official guidance.
        is_query = len(texts) == 1
        if self._model.startswith("gemini-embedding-2"):
            if is_query:
                prepared = [f"task: search result | query: {texts[0]}"]
            else:
                prepared = [f"title: none | text: {t}" for t in texts]
            embed_cfg = None
        else:
            prepared = texts
            # For gemini-embedding-001 and similar, use taskType when possible.
            embed_cfg = {
                "taskType": "RETRIEVAL_QUERY" if is_query else "RETRIEVAL_DOCUMENT",
            }

        url = f"{self._base_url}/{model_name}:batchEmbedContents?key={self._api_key}"
        headers = {"Content-Type": "application/json"}
        payload = {
            "requests": [
                {
                    "model": model_name,
                    "content": {"parts": [{"text": t}]},
                    **({"embedContentConfig": embed_cfg} if embed_cfg else {}),
                }
                for t in prepared
            ]
        }

        data = _request_with_retries(url, headers=headers, payload=payload, timeout_s=self._timeout_s)
        embeddings = data.get("embeddings")
        if not isinstance(embeddings, list):
            raise EmbeddingError("Malformed Gemini embedding response: missing embeddings[]")

        out: list[list[float]] = []
        for emb in embeddings:
            if isinstance(emb, dict) and isinstance(emb.get("values"), list):
                out.append(emb["values"])
            elif isinstance(emb, dict) and isinstance(emb.get("embedding"), dict) and isinstance(emb["embedding"].get("values"), list):
                out.append(emb["embedding"]["values"])
            else:
                raise EmbeddingError("Malformed Gemini embedding response: embedding missing values[]")

        if len(out) != len(texts):
            raise EmbeddingError(f"Gemini embedding API returned {len(out)} items for {len(texts)} inputs")

        return out


def create_embedding_client(config: EmbeddingConfig) -> EmbeddingClient:
    provider = config.provider

    if provider in {"openai", "openai_compatible"}:
        return OpenAIEmbeddingClient(
            api_key=config.api_key or "",
            base_url=config.base_url or "https://api.openai.com/v1",
            model=config.model or "text-embedding-3-small",
        )

    if provider in {"azure", "azure_openai"}:
        return AzureOpenAIEmbeddingClient(
            api_key=config.api_key or "",
            endpoint=config.azure_endpoint or "",
            deployment=config.azure_deployment or "",
            api_version=config.azure_api_version or "2024-02-15-preview",
        )

    if provider in {"google_ai_studio", "google-aistudio", "gemini", "google"}:
        return GoogleAIStudioEmbeddingClient(
            api_key=config.api_key or "",
            base_url=config.base_url or "https://generativelanguage.googleapis.com/v1beta",
            model=config.model or "gemini-embedding-2",
        )

    raise EmbeddingError(f"Unknown embedding provider: {provider}")


def _request_with_retries(
    url: str,
    *,
    headers: dict[str, str],
    payload: dict,
    timeout_s: int,
    max_retries: int = 8,
) -> dict:
    backoff_s = 1.0
    last_err: Exception | None = None

    for attempt in range(max_retries):
        try:
            resp = requests.post(url, headers=headers, json=payload, timeout=timeout_s)
            if resp.status_code == 200:
                return resp.json()

            # Rate limit / transient errors
            if resp.status_code in {408, 409, 429, 500, 502, 503, 504}:
                time.sleep(backoff_s)
                backoff_s = min(backoff_s * 1.8, 20.0)
                continue

            raise EmbeddingError(f"Embedding request failed ({resp.status_code}): {resp.text[:500]}")
        except EmbeddingError:
            raise
        except Exception as e:  # noqa: BLE001
            last_err = e
            time.sleep(backoff_s)
            backoff_s = min(backoff_s * 1.8, 20.0)

    raise EmbeddingError(f"Embedding request failed after retries: {last_err}")
