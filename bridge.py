"""Offline process/RPC boundary only. The actual vendor entry is disabled.

No HTTP client, credential resolver, SDK, environment secret lookup or default
process is created at import. This is not an OS network sandbox.
"""
import asyncio
import base64
import hashlib
import json
import math
from pathlib import Path
import re
import subprocess
import sys
import time
from urllib.parse import parse_qsl, urlsplit

from global_quota_v2 import RequestPermit

HOST = "hackathon.api.qloo.com"
ARCHIVE_SHA256 = "95529b2ac520450e5a2c9701a9baa1d2eccf52f15ccd6ef408aec86397d13ed6"
FIXTURE = Path(__file__).with_name("fixture_child.py")
MAX_OUTPUT = 196608
MAX_LINE = 180224
MAX_RAW_BYTES = 131072
MAX_STDERR = 4096


class BridgeError(RuntimeError):
    """Sanitized failure, deliberately excluding child data and exceptions."""


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def strict_json(raw):
    def pairs(values):
        out = {}
        for k, v in values:
            if k in out:
                raise ValueError()
            out[k] = v
        return out
    def constant(_):
        raise ValueError()
    value = json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
    def check(x, depth=0):
        if depth > 16:
            raise ValueError()
        if isinstance(x, float) and not math.isfinite(x):
            raise ValueError()
        if isinstance(x, (dict, list)):
            if len(x) > 200:
                raise ValueError()
            for y in x.values() if isinstance(x, dict) else x:
                check(y, depth + 1)
    check(value)
    return value


def validate_request(request):
    if (not isinstance(request, dict) or set(request) != {"surface", "operation", "input"}
            or request["surface"] != "qloo exec" or request["operation"] not in {"describe", "recommend"}
            or not isinstance(request["input"], dict)):
        raise BridgeError("Unsupported bounded workflow request.")
    try:
        value = request["input"]
        if request["operation"] == "describe":
            if (set(value) != {"entity", "type"} or value["type"] != "artist"
                    or not isinstance(value["entity"], str) or not 1 <= len(value["entity"]) <= 120
                    or value["entity"] != value["entity"].strip()
                    or any(ord(c) < 32 for c in value["entity"])):
                raise ValueError()
        elif (set(value) != {"target_type", "signals", "explain", "limit"}
                or value["target_type"] != "artist" or value["explain"] is not False
                or type(value["limit"]) is not int or value["limit"] != 3
                or not isinstance(value["signals"], list) or len(value["signals"]) != 2
                or any(not isinstance(v, str) or not re.fullmatch(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}", v) for v in value["signals"])
                or len({v.lower() for v in value["signals"]}) != 2):
            raise ValueError()
        raw = canonical(request).encode()
        if len(raw) > 4096:
            raise ValueError()
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise BridgeError("Unsupported bounded workflow request.") from None
    return hashlib.sha256(raw).hexdigest()


def validate_raw_url(url):
    if not isinstance(url, str) or len(url) > 4096 or any(c in url for c in "\r\n\x00"):
        raise BridgeError("Raw request destination refused.")
    try:
        u = urlsplit(url)
        if (u.scheme != "https" or u.netloc != HOST or u.hostname != HOST
                or u.username is not None or u.password is not None or u.fragment
                or u.path not in {"/search", "/entities", "/v2/insights"}):
            raise ValueError()
        fields = parse_qsl(u.query, keep_blank_values=True, strict_parsing=True, max_num_fields=16)
        if not fields or len({k for k, _ in fields}) != len(fields):
            raise ValueError()
        allowed = {"query", "types", "take", "entity_ids", "filter.type", "signal.interests.entities",
                   "filter.exclude.entities", "feature.explainability"}
        if any(k not in allowed or not v or len(v) > 1024 or any(ord(c) < 32 for c in v) for k, v in fields):
            raise ValueError()
    except (ValueError, UnicodeError):
        raise BridgeError("Raw request destination refused.") from None
    return url


class OfflineProcessBridge:
    """Exercise one locally authored fixture process, never the Qloo package.

    The raw callback is trusted injected server code and must perform exactly
    one I/O if ever replaced. Tests inject a no-I/O callback. No API key reaches
    the child. A future vendor shim must implement this reviewed protocol and
    prove its complete startup/network path before enablement.
    """
    def __init__(self, *, fixture_sha256, scenario="success", forbidden_fragments=()):
        if (not isinstance(fixture_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", fixture_sha256)
                or scenario not in {"success", "two_raw", "duplicate_raw", "wrong_host", "redirect", "wrong_source", "nonfinite_result", "escaped_result", "escaped_url", "percent_url",
                                    "stdout_flood", "stderr_flood", "key_echo", "hang", "exit_error"}):
            raise ValueError("Use an explicitly pinned offline fixture.")
        if not isinstance(forbidden_fragments, (tuple, list)) or any(
                not isinstance(v, bytes) or not 8 <= len(v) <= 4096 for v in forbidden_fragments):
            raise ValueError("Use bounded caller-supplied forbidden fragments.")
        self.fixture_sha256 = fixture_sha256
        self.scenario = scenario
        self.forbidden = tuple(forbidden_fragments)
        self.last_pid = None
        self.last_returncode = None

    async def run_vendor(self, *args, **kwargs):
        raise BridgeError("Actual Qloo package startup and raw-request interception are not qualified; vendor execution is disabled.")

    def _check_secret(self, raw):
        if any(v in raw for v in self.forbidden):
            raise BridgeError("Child or transport output contained a forbidden fragment; nothing was accepted.")

    def _check_value(self, value):
        """Literal UTF-8 and JSON escape decoding only; not arbitrary encoding detection."""
        if isinstance(value, str):
            self._check_secret(value.encode('utf-8'))
        elif isinstance(value, dict):
            for key, item in value.items():
                self._check_value(key)
                self._check_value(item)
        elif isinstance(value, list):
            for item in value: self._check_value(item)

    def _launch_command(self):
        if FIXTURE.is_symlink() or hashlib.sha256(FIXTURE.read_bytes()).hexdigest() != self.fixture_sha256:
            raise ValueError()
        return [sys.executable, '-I', '-u', str(FIXTURE), self.scenario]

    def _launch_environment(self):
        return {"PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8"}

    async def run(self, request, *, permit, raw_transport, timeout_seconds=2, max_response_bytes=MAX_RAW_BYTES):
        request_hash = validate_request(request)
        self._check_secret(canonical(request).encode())
        self._check_value(request)
        if (not isinstance(permit, RequestPermit) or permit.app_id != "qloo" or not callable(raw_transport)
                or isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, (int, float))
                or not 0.05 <= timeout_seconds <= 10 or type(max_response_bytes) is not int
                or not 1 <= max_response_bytes <= MAX_RAW_BYTES):
            raise BridgeError("Explicit Qloo permit, single-request transport and bounded limits required.")
        try:
            command = self._launch_command()
        except (ValueError, OSError):
            raise BridgeError("Offline process source is unavailable or does not match its reviewed hash.") from None
        process = None
        stderr_task = None
        deadline = time.monotonic() + timeout_seconds
        self.last_pid = self.last_returncode = None

        async def consume_stderr():
            total = 0
            tail = b""
            keep = max((len(v) - 1 for v in self.forbidden), default=0)
            while True:
                chunk = await process.stderr.read(1024)
                if not chunk:
                    return
                total += len(chunk)
                self._check_secret(tail + chunk)
                if total > MAX_STDERR:
                    raise BridgeError("Child diagnostic output exceeded its bound.")
                tail = (tail + chunk)[-keep:] if keep else b""

        async def bounded(awaitable):
            left = deadline - time.monotonic()
            if left <= 0:
                if hasattr(awaitable, "close"):
                    awaitable.close()
                raise TimeoutError()
            return await asyncio.wait_for(awaitable, left)

        async def run_protocol():
            nonlocal process, stderr_task
            options = {"creationflags": subprocess.CREATE_NO_WINDOW} if sys.platform == "win32" else {}
            # Explicit small environment avoids inheriting caller credentials,
            # profile paths, provider variables or global configuration.
            process = await bounded(asyncio.create_subprocess_exec(
                *command,
                stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE, limit=MAX_LINE,
                env=self._launch_environment(), **options))
            self.last_pid = process.pid
            stderr_task = asyncio.create_task(consume_stderr())
            process.stdin.write((canonical({"type": "workflow", "request": request, "request_sha256": request_hash}) + "\n").encode())
            await bounded(process.stdin.drain())
            total, sequence = 0, 0
            result = None
            while True:
                if stderr_task.done():
                    await stderr_task
                line_task = asyncio.create_task(process.stdout.readline())
                done, _ = await asyncio.wait({line_task, stderr_task}, timeout=max(0, deadline-time.monotonic()), return_when=asyncio.FIRST_COMPLETED)
                if stderr_task in done:
                    try:
                        await stderr_task
                    except BaseException:
                        line_task.cancel()
                        await asyncio.gather(line_task, return_exceptions=True)
                        raise
                if line_task not in done:
                    if stderr_task.done():
                        line = await bounded(line_task)
                    else:
                        line_task.cancel()
                        await asyncio.gather(line_task, return_exceptions=True)
                        raise TimeoutError()
                else:
                    line = line_task.result()
                if not line:
                    break
                total += len(line)
                if total > MAX_OUTPUT or len(line) > MAX_LINE:
                    raise BridgeError("Child workflow output exceeded its bound.")
                self._check_secret(line)
                msg = strict_json(line)
                self._check_value(msg)
                if not isinstance(msg, dict) or msg.get("request_sha256") != request_hash:
                    raise BridgeError("Child workflow/source binding failed.")
                if msg.get("type") == "raw_request" and result is None:
                    if set(msg) != {"type", "request_sha256", "sequence", "method", "url"} or type(msg["sequence"]) is not int or msg["sequence"] != sequence+1 or msg["method"] != "GET":
                        raise BridgeError("Unsupported raw request frame.")
                    sequence += 1
                    if sequence > 16:
                        raise BridgeError("Raw request frame budget exhausted.")
                    url = validate_raw_url(msg["url"])
                    self._check_value(dict(parse_qsl(urlsplit(url).query)))
                    descriptor = hashlib.sha256(canonical({"method":"GET", "url":url}).encode()).hexdigest()
                    response = await bounded(permit.invoke_raw_async(descriptor,
                        lambda: raw_transport(method="GET", url=url, timeout_seconds=max(0.01, deadline-time.monotonic()), max_response_bytes=max_response_bytes)))
                    if (not isinstance(response, dict) or set(response) != {"status", "body"}
                            or type(response["status"]) is not int or not 200 <= response["status"] <= 299
                            or not isinstance(response["body"], bytes)
                            or len(response["body"]) > max_response_bytes):
                        raise BridgeError("Raw response refused; no failure continuation, redirect, fallback or automatic retry is available.")
                    self._check_secret(response["body"])
                    self._check_value(strict_json(response["body"]))
                    process.stdin.write((canonical({"type":"raw_response", "sequence":sequence,
                        "status":response["status"], "body_b64":base64.b64encode(response["body"]).decode()})+"\n").encode())
                    await bounded(process.stdin.drain())
                elif msg.get("type") == "result" and result is None:
                    if set(msg) != {"type", "request_sha256", "operation", "body_b64"} or msg["operation"] != request["operation"] or not isinstance(msg["body_b64"], str):
                        raise BridgeError("Unsupported workflow result frame.")
                    result = base64.b64decode(msg["body_b64"], validate=True)
                    if len(result) > max_response_bytes:
                        raise BridgeError("Workflow result exceeded its bound.")
                    self._check_secret(result)
                    decoded_result = strict_json(result)
                    self._check_value(decoded_result)
                    if not isinstance(decoded_result, dict):
                        raise BridgeError("A structured workflow result is required.")
                else:
                    raise BridgeError("Unexpected, repeated or late workflow frame.")
            await bounded(process.wait())
            await bounded(stderr_task)
            self.last_returncode = process.returncode
            if process.returncode != 0 or result is None:
                raise BridgeError("Child workflow did not complete successfully.")
            return result

        try:
            return await run_protocol()
        except asyncio.CancelledError:
            permit.close()
            raise
        except BaseException as error:
            permit.close()
            if isinstance(error, (KeyboardInterrupt, SystemExit)):
                raise
            raise BridgeError("Offline process request failed or became uncertain; no retry occurred.") from None
        finally:
            if process is not None:
                if process.returncode is None:
                    try:
                        process.kill()
                    except ProcessLookupError:
                        pass
                await process.wait()
                self.last_returncode = process.returncode
            if stderr_task is not None:
                if not stderr_task.done():
                    stderr_task.cancel()
                await asyncio.gather(stderr_task, return_exceptions=True)
