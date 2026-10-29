"""Private typed callable tools through the SAME signed handler; not MCP/RPC.

The trusted in-process host supplies an already issued anonymous demo session.
It must show identity candidates and collect explicit selection before calling
recommend_confirmed_pair. This adapter checks exact pair/source/session data;
it does not prove who selected IDs or bypass any native approval requirement.
"""
from copy import deepcopy
import json
import re
import secrets
from urllib.parse import urlsplit

from qloo_composition import QlooComposition

FIELDS = {
    "resolve_artist_pair": {"queries", "request_id"},
    "recommend_confirmed_pair": {"queries", "resolution_id", "selected_ids", "request_id"},
}
DESCRIPTIONS = {
    "resolve_artist_pair": "Resolve exactly two names into candidates. Return choices for explicit identity review; never select a candidate automatically.",
    "recommend_confirmed_pair": "Inspect a combined result for the explicitly selected pair bound to its stored resolution. The host must collect identity selection first; this tool does not verify human origin.",
}


class ToolInputError(ValueError):
    pass


def tool_definitions():
    definitions = []
    for name, fields in FIELDS.items():
        properties = {"queries": {"type": "array", "minItems": 2, "maxItems": 2,
            "items": {"type": "string", "minLength": 2, "maxLength": 80}},
            "request_id": {"type": "string", "pattern": "^[A-Za-z0-9_.:-]{8,32}$"}}
        if name == "recommend_confirmed_pair":
            properties.update(resolution_id={"type": "string", "pattern": "^[0-9a-f]{64}$"},
                selected_ids={"type": "array", "minItems": 2, "maxItems": 2, "uniqueItems": True,
                              "items": {"type": "string", "format": "uuid", "pattern": "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"}})
        definitions.append({"name": name, "description": DESCRIPTIONS[name],
            "inputSchema": {"type": "object", "additionalProperties": False,
                "required": sorted(fields), "properties": properties},
            "scope": "configured_unverified", "executionAuthority": "none"})
    return definitions


def _validate(name, arguments):
    if name not in FIELDS or type(arguments) is not dict or set(arguments) != FIELDS[name]:
        raise ToolInputError("Use one listed tool with exactly its declared fields.")
    queries, request_id = arguments["queries"], arguments["request_id"]
    if (type(queries) is not list or len(queries) != 2
            or any(type(q) is not str or not 2 <= len(q) <= 80 for q in queries)
            or type(request_id) is not str or not re.fullmatch(r"[A-Za-z0-9_.:-]{8,32}", request_id)):
        raise ToolInputError("Use two bounded names and one explicit operation ID.")
    if name == "recommend_confirmed_pair":
        selected = arguments["selected_ids"]
        if (type(arguments["resolution_id"]) is not str
                or not re.fullmatch(r"[0-9a-f]{64}", arguments["resolution_id"])
                or type(selected) is not list or len(selected) != 2
                or any(type(value) is not str or not re.fullmatch(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}", value) for value in selected)
                or len({value.lower() for value in selected}) != 2):
            raise ToolInputError("Supply the exact reviewed resolution and two explicitly selected distinct UUIDs.")
    return deepcopy(arguments)


class QlooPairTools:
    def __init__(self, handler, *, session_cookie, admission_id_factory=None):
        if not isinstance(handler, QlooComposition):
            raise ValueError("Bind the reviewed private Qloo composition.")
        if (type(session_cookie) is not str or len(session_cookie) > 4096
                or not session_cookie.startswith(handler.cookie_name + "=")
                or ";" in session_cookie or "\n" in session_cookie or "\r" in session_cookie):
            raise ValueError("Supply exactly one already issued private demo cookie.")
        if admission_id_factory is not None and not callable(admission_id_factory):
            raise ValueError("Use an explicit trusted ID factory or local random IDs.")
        self.handler, self.cookie = handler, session_cookie
        self._ids = admission_id_factory or (lambda: secrets.token_hex(16))

    def call(self, name, arguments):
        packet = _validate(name, arguments)
        admission = self._ids()
        if type(admission) is not str or not re.fullmatch(r"[A-Za-z0-9_-]{16,80}", admission):
            raise ToolInputError("The trusted host supplied an invalid admission ID.")
        path = "/api/resolve" if name == "resolve_artist_pair" else "/api/shortlist"
        source = self.handler.config
        host = urlsplit(source.origin).netloc
        session = self.cookie.split("=", 1)[1]
        event = {"version": "2.0", "rawPath": path, "rawQueryString": "",
            "requestContext": {"domainName": host, "http": {"method": "POST"}},
            "headers": {"host": host, "x-forwarded-proto": "https", "origin": source.origin,
                "sec-fetch-site": "same-origin", "content-type": "application/json",
                "x-demo-revision": source.source_revision, "x-demo-request": admission,
                "x-demo-nonce": self.handler._nonce(session, path)},
            "cookies": [self.cookie], "body": json.dumps(packet, allow_nan=False), "isBase64Encoded": False}
        response = self.handler(event)
        data = json.loads(response["body"])
        return {"status": "ok" if response["statusCode"] == 200 else "error",
            "http_status": response["statusCode"], "data": data,
            "provenance": "configured_unverified", "external_execution_verified": False,
            "identity_selection_origin_verified": False, "execution_authority": "none"}
