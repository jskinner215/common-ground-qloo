"""Private narrow async GET candidate. No client, secret or network on import."""
from contextlib import asynccontextmanager
import hashlib
import inspect
import json
import math
from urllib.parse import unquote, urlsplit

from async_host import current_scope

HOST = "hackathon.api.qloo.com"
PATHS = {"/search", "/entities", "/v2/insights"}
REVIEWED_AIOHTTP_VERSION = "3.13.5"
REVIEWED_CLIENT_SOURCE_SHA256 = "2641c6aeb26ad69488ed0109c348d92b1e532cbcccf3ba1ff18c7eeb69b8c7a8"
MAX_BYTES = 131072
CHUNK_BYTES = 1024
MAX_HEADERS = 32
MAX_HEADER_FIELD = 1024
MAX_HEADER_BYTES = 8192


class TransportRefusal(RuntimeError):
    pass


def _descriptor(method, url, timeout_seconds, max_response_bytes):
    if method != "GET" or not isinstance(url, str) or len(url) > 8192:
        raise TransportRefusal("Use one bounded fixed-host GET descriptor.")
    try:
        parsed = urlsplit(url)
        decoded = unquote(url, errors="strict")
    except (ValueError, UnicodeError):
        raise TransportRefusal("Invalid URL.") from None
    if (parsed.scheme != "https" or parsed.netloc != HOST or parsed.path not in PATHS
            or parsed.fragment or any(ord(c) <= 32 or ord(c) >= 127 for c in url)
            or any(ord(c) < 32 or ord(c) == 127 for c in decoded)):
        raise TransportRefusal("Only the assigned HTTPS host and reviewed GET paths are accepted.")
    if (type(timeout_seconds) not in (int, float) or not math.isfinite(timeout_seconds)
            or not 0 < timeout_seconds <= 3 or type(max_response_bytes) is not int
            or not 0 < max_response_bytes <= MAX_BYTES):
        raise TransportRefusal("Use the explicit bounded raw request limits.")


@asynccontextmanager
async def _new_session(timeout_seconds):
    from importlib.metadata import distribution, version
    if version("aiohttp") != REVIEWED_AIOHTTP_VERSION:
        raise TransportRefusal("HTTP dependency differs from the reviewed version.")
    client_source = distribution("aiohttp").locate_file("aiohttp/client.py").resolve()
    if hashlib.sha256(client_source.read_bytes()).hexdigest() != REVIEWED_CLIENT_SOURCE_SHA256:
        raise TransportRefusal("HTTP retry implementation differs from the reviewed source.")
    import ssl
    import aiohttp
    from pathlib import Path
    if Path(aiohttp.client.__file__).resolve() != client_source:
        raise TransportRefusal("Loaded HTTP implementation differs from the reviewed source.")
    tls = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
    tls.check_hostname = True
    tls.verify_mode = ssl.CERT_REQUIRED
    tls.minimum_version = ssl.TLSVersion.TLSv1_2
    connector = aiohttp.TCPConnector(ssl=tls, limit=1, limit_per_host=1,
        force_close=True, use_dns_cache=False, timeout_ceil_threshold=60,
        ssl_shutdown_timeout=0)
    timeout = aiohttp.ClientTimeout(total=timeout_seconds, connect=timeout_seconds,
        sock_connect=timeout_seconds, sock_read=timeout_seconds, ceil_threshold=60)
    try:
        async with aiohttp.ClientSession(connector=connector, timeout=timeout,
            trust_env=False, cookie_jar=aiohttp.DummyCookieJar(), auto_decompress=False,
            read_bufsize=CHUNK_BYTES, max_line_size=MAX_HEADER_FIELD,
            max_field_size=MAX_HEADER_FIELD, max_headers=MAX_HEADERS,
            raise_for_status=False, middlewares=(), trace_configs=[],
            skip_auto_headers={"User-Agent"}, ssl_shutdown_timeout=0) as session:
            # aiohttp3.13.5 otherwise retries idempotent GET after connection
            # reset/disconnect. That would violate one permit per raw attempt.
            # This private attribute is supported only by the pinned source.
            if getattr(session, "_retry_connection", None) is not True:
                raise TransportRefusal("Unexpected HTTP retry-policy shape.")
            session._retry_connection = False
            if session._retry_connection is not False:
                raise TransportRefusal("HTTP connection retries were not disabled.")
            yield session
    finally:
        await connector.close(abort_ssl=True)


def _headers(raw_headers):
    if not isinstance(raw_headers, (tuple, list)) or len(raw_headers) > MAX_HEADERS:
        raise TransportRefusal("Response header count exceeds its bound.")
    total = 0
    for row in raw_headers:
        if not isinstance(row, tuple) or len(row) != 2 or any(not isinstance(v, bytes) for v in row):
            raise TransportRefusal("Unexpected response header representation.")
        if len(row[0]) + len(row[1]) > MAX_HEADER_FIELD:
            raise TransportRefusal("Response header field exceeds its bound.")
        total += len(row[0]) + len(row[1]) + 4
    if total > MAX_HEADER_BYTES:
        raise TransportRefusal("Response headers exceed their aggregate bound.")


def _final_url(response, requested_url):
    # Pinned aiohttp builds its actual request URL with yarl.URL(str_or_url).
    # Use that same canonicalization for the approved descriptor, preserving
    # query order/duplicates rather than decoding signals into a mapping.
    from yarl import URL
    expected = URL(requested_url)
    actual = getattr(response, "url", None)
    if (type(actual) is not URL or actual != expected
            or actual.scheme != "https" or actual.raw_authority != HOST
            or actual.raw_user is not None or actual.raw_password is not None
            or actual.explicit_port is not None or actual.raw_fragment):
        raise TransportRefusal("The final response URL differs from the approved request.")


def _no_secret_body(body, key):
    if key.encode("ascii") in body:
        raise TransportRefusal("Response failed the no-credential-output boundary.")
    try:
        value = json.loads(body)
    except (ValueError, UnicodeError, RecursionError):
        raise TransportRefusal("Expected bounded JSON response.") from None
    pending, count = [(value, 0)], 0
    while pending:
        node, depth = pending.pop()
        count += 1
        if depth > 32 or count > 4096:
            raise TransportRefusal("Response JSON structure exceeds its bound.")
        if isinstance(node, str) and key in node:
            raise TransportRefusal("Response failed the no-credential-output boundary.")
        if isinstance(node, dict):
            pending.extend((child, depth + 1) for pair in node.items() for child in pair)
        elif isinstance(node, list):
            pending.extend((child, depth + 1) for child in node)


def make_raw_get_transport(*, credential_provider, admission_check,
                           network_enabled=False, session_factory=None):
    """Build inert callback. Booleans/callbacks are not user authorization.

    The trusted caller must bind admission_check to the actual source/session
    RequestPermit. The bridge remains responsible for reserving each raw call.
    No key is read until a valid admitted descriptor reaches an owned host.
    """
    if not callable(credential_provider) or not callable(admission_check):
        raise TransportRefusal("Inject explicit credential and admission providers.")

    async def raw_get(*, method, url, timeout_seconds, max_response_bytes):
        if network_enabled is not True:
            raise TransportRefusal("Network transport remains disabled.")
        _descriptor(method, url, timeout_seconds, max_response_bytes)
        scope = current_scope()
        if admission_check() is not True:
            raise TransportRefusal("An exact admitted source/session permit is required.")
        import asyncio
        loop = asyncio.get_running_loop()
        left = min(timeout_seconds, scope.remaining())
        deadline_at = loop.time() + left
        try:
            async with asyncio.timeout_at(deadline_at):
                key = credential_provider()
                if inspect.isawaitable(key):
                    key = await key
                if (not isinstance(key, str) or not 8 <= len(key) <= 4096
                        or any(ord(c) <= 32 or ord(c) >= 127 for c in key)):
                    raise TransportRefusal("Use one bounded header-safe credential.")
                if key in url or key in unquote(url):
                    raise TransportRefusal("A credential must never appear in a URL.")
                factory = session_factory or _new_session
                async with factory(min(left, scope.remaining())) as session:
                    scope.remaining()
                    if loop.time() >= deadline_at:
                        raise TimeoutError()
                    if admission_check() is not True:
                        raise TransportRefusal("Admission changed before I/O; no GET was started.")
                    headers = {"X-Api-Key": key, "Accept": "application/json",
                               "Accept-Encoding": "identity"}
                    async with session.get(url, headers=headers, allow_redirects=False,
                                           proxy=None, read_until_eof=False) as response:
                        try:
                            _final_url(response, url)
                            _headers(response.raw_headers)
                            if type(response.status) is not int or not 100 <= response.status <= 599:
                                raise TransportRefusal("Unexpected HTTP status.")
                            if response.status != 200:
                                return {"status": response.status, "body": b""}
                            if response.headers.get("Content-Encoding", "identity").lower() not in ("", "identity"):
                                raise TransportRefusal("Compressed response is refused.")
                            if response.headers.get("Content-Type", "").split(";")[0].strip().lower() != "application/json":
                                raise TransportRefusal("Expected JSON response content type.")
                            if response.content_length is not None and response.content_length > max_response_bytes:
                                raise TransportRefusal("Advertised response exceeds its byte bound.")
                            body = bytearray()
                            async for chunk in response.content.iter_chunked(CHUNK_BYTES):
                                scope.remaining()
                                if not isinstance(chunk, bytes) or len(body) + len(chunk) > max_response_bytes:
                                    raise TransportRefusal("Response exceeds its byte bound.")
                                body.extend(chunk)
                            body = bytes(body)
                            _no_secret_body(body, key)
                            scope.remaining()
                            if loop.time() >= deadline_at:
                                raise TimeoutError()
                            return {"status": 200, "body": body}
                        finally:
                            response.close()
        except asyncio.CancelledError:
            raise
        except TimeoutError:
            raise TimeoutError("HTTP deadline expired; execution is uncertain and no retry occurred.") from None
        except Exception:
            raise TransportRefusal("HTTP attempt failed; no retry occurred and execution is uncertain.") from None
    return raw_get
