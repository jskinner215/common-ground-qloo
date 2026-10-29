"""Original private Qloo preparation. Local synthetic contract, not a vendor schema."""
from datetime import datetime, timezone
from fractions import Fraction
import hashlib
import json
import re
import unicodedata


class WorkflowError(Exception):
    def __init__(self, code, message, status=400):
        super().__init__(message)
        self.code, self.message, self.status = code, message, status


PROVIDER = {"status": "disconnected", "mode": "synthetic_only",
            "qualification": "Live Qloo is not connected. Vendor schema is unverified; all artists and results here are fictional."}
SEEDS = [
    {"id": "synthetic:seed:juniper", "label": "Juniper Echo", "type": "artist"},
    {"id": "synthetic:seed:lantern", "label": "North Lantern", "type": "artist"},
    {"id": "synthetic:seed:echo-coast", "label": "Echo Coast", "type": "artist"},
    {"id": "synthetic:seed:echo-trio", "label": "Echo Trio", "type": "artist"},
    {"id": "synthetic:seed:silent", "label": "Silent Orchard", "type": "artist"},
    {"id": "synthetic:seed:empty", "label": "Empty Station", "type": "artist"},
]
ITEMS = {
    "quiet": {"id": "synthetic:artist:quiet", "label": "Quiet Room", "type": "artist"},
    "comet": {"id": "synthetic:artist:comet", "label": "Comet Paper", "type": "artist"},
    "tide": {"id": "synthetic:artist:tide", "label": "Tide Window", "type": "artist"},
    "moth": {"id": "synthetic:artist:moth", "label": "Moth Atlas", "type": "artist"},
    "lake": {"id": "synthetic:artist:lake", "label": "Lake Index", "type": "artist"},
}
FIXTURE_ORDER = {
    "synthetic:seed:juniper": ["quiet", "comet", "tide"],
    "synthetic:seed:lantern": ["moth", "quiet", "comet"],
    "synthetic:seed:echo-coast": ["lake"],
    "synthetic:seed:echo-trio": ["tide", "quiet"],
    "synthetic:seed:silent": [], "synthetic:seed:empty": [],
}


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False,
                                     separators=(",", ":"), allow_nan=False).encode()).hexdigest()


def clean_text(value, maximum=80):
    if not isinstance(value, str):
        raise WorkflowError("invalid_text", "Use text for each artist name.")
    text = unicodedata.normalize("NFKC", value.strip())
    if not 1 <= len(text) <= maximum or any(unicodedata.category(c).startswith("C") for c in text):
        raise WorkflowError("invalid_text", f"Use 1 to {maximum} visible characters.")
    return text


def validate_queries(queries):
    if not isinstance(queries, list) or len(queries) != 2:
        raise WorkflowError("invalid_queries", "Provide exactly two artist names.")
    queries = [clean_text(q) for q in queries]
    if any(len(q) < 2 for q in queries):
        raise WorkflowError("short_query", "Use at least two characters to resolve an artist.")
    return queries


def validate_entities(items, maximum=40):
    if not isinstance(items, list) or len(items) > maximum:
        raise WorkflowError("invalid_results", "The synthetic adapter returned an invalid result list.", 502)
    checked, seen = [], set()
    for item in items:
        if (not isinstance(item, dict) or set(item) != {"id", "label", "type"}
                or item["type"] != "artist" or not isinstance(item["id"], str)
                or not re.fullmatch(r"synthetic:[a-z0-9:_-]{1,72}", item["id"])):
            raise WorkflowError("invalid_results", "Unverified entity structure was refused.", 502)
        try:
            label = clean_text(item["label"], 120)
        except WorkflowError:
            raise WorkflowError("invalid_results", "An invalid result label was refused.", 502)
        if item["id"] in seen:
            raise WorkflowError("duplicate_result", "Duplicate entity IDs were refused.", 502)
        seen.add(item["id"])
        checked.append({"id": item["id"], "label": label, "type": "artist"})
    return checked


FIXTURE_ID = "original-fictional-artists-v1"
FIXTURE_HASH = digest({"seeds": SEEDS, "items": ITEMS, "order": FIXTURE_ORDER})


def resolve(queries):
    queries = validate_queries(queries)
    choices = []
    for query in queries:
        candidates = validate_entities([dict(s) for s in SEEDS if query.casefold() in s["label"].casefold()])
        choices.append({"query": query, "state": "none" if not candidates else "ambiguous" if len(candidates) > 1 else "one_candidate",
                        "candidates": candidates})
    payload = {"queries": queries, "choices": choices, "fixture_id": FIXTURE_ID, "fixture_hash": FIXTURE_HASH}
    return {**payload, "resolution_id": digest(payload), "provider": dict(PROVIDER)}


class QlooAdapter:
    """No endpoints or credential access until authorized vendor schema mapping exists."""
    def recommendations(self, seed_id):
        raise WorkflowError("provider_disconnected", "Live Qloo access is not connected or qualified.", 503)


class SyntheticAdapter:
    def recommendations(self, seed_id):
        if seed_id not in FIXTURE_ORDER:
            raise WorkflowError("unknown_seed", "This synthetic seed is not supported.")
        payload = {"mode": "synthetic", "seed_id": seed_id, "fixture_id": FIXTURE_ID,
                   "items": [dict(ITEMS[key]) for key in FIXTURE_ORDER[seed_id]]}
        return {**payload, "source_receipt_id": digest(payload)}


def validate_result(payload, seed_id):
    if (not isinstance(payload, dict) or set(payload) != {"mode", "seed_id", "fixture_id", "items", "source_receipt_id"}
            or payload["mode"] != "synthetic" or payload["seed_id"] != seed_id or payload["fixture_id"] != FIXTURE_ID):
        raise WorkflowError("invalid_provenance", "Adapter source identity or mode was refused.", 502)
    items = validate_entities(payload["items"])
    core = {k: payload[k] for k in ["mode", "seed_id", "fixture_id", "items"]}
    if not isinstance(payload["source_receipt_id"], str) or digest(core) != payload["source_receipt_id"]:
        raise WorkflowError("invalid_provenance", "Adapter receipt does not match the returned data.", 502)
    return items


def shortlist(queries, resolution_id, selected_ids, adapter=None):
    resolution = resolve(queries)
    if not isinstance(resolution_id, str) or resolution_id != resolution["resolution_id"]:
        raise WorkflowError("stale_resolution", "Artist names or source data changed. Resolve and confirm the pair again.", 409)
    if not isinstance(selected_ids, list) or len(selected_ids) != 2 or any(not isinstance(i, str) for i in selected_ids):
        raise WorkflowError("invalid_pair", "Confirm one artist from each resolution.")
    for index, selected in enumerate(selected_ids):
        if selected not in {c["id"] for c in resolution["choices"][index]["candidates"]}:
            raise WorkflowError("unconfirmed_artist", "A selected artist was not in that name's reviewed candidates.")
    if selected_ids[0] == selected_ids[1]:
        raise WorkflowError("same_artist", "Choose two different artists for this shared shortlist.")
    selected = [next(c for c in resolution["choices"][i]["candidates"] if c["id"] == ident)
                for i, ident in enumerate(selected_ids)]
    adapter = adapter if adapter is not None else SyntheticAdapter()
    sources, combined = [], {}
    for seed in selected:
        response = adapter.recommendations(seed["id"])
        items = validate_result(response, seed["id"])
        sources.append({"seed_id": seed["id"], "source_receipt_id": response["source_receipt_id"],
                        "fixture_id": FIXTURE_ID, "data_hash": digest(items), "candidate_count": len(items)})
        for rank, item in enumerate(items, 1):
            if item["id"] in selected_ids:
                continue
            existing = combined.setdefault(item["id"], {**item, "support": []})
            if existing["label"] != item["label"]:
                raise WorkflowError("conflicting_entity", "Two sources gave conflicting labels for one entity ID.", 502)
            existing["support"].append({"seed_id": seed["id"], "seed_label": seed["label"], "rank": rank,
                                        "source_receipt_id": response["source_receipt_id"]})
    ranked = sorted(combined.values(), key=lambda i: (-sum(Fraction(1, 60 + s["rank"]) for s in i["support"]), i["id"]))
    shared = [item for item in ranked if len(item["support"]) == 2]
    one_seed = [item for item in ranked if len(item["support"]) == 1]
    result = {"mode": "synthetic", "provider": dict(PROVIDER), "resolution_id": resolution_id,
              "selected": selected, "state": "shared" if shared else "one_seed_only" if one_seed else "none",
              "shared": shared[:3], "one_seed": one_seed[:3],
              "omitted": {"shared": max(0, len(shared) - 3), "one_seed": max(0, len(one_seed) - 3)},
              "ranking": "Local reciprocal-rank fusion, sum(1/(60+rank)); not a Qloo score or a prediction that either person will like an artist.",
              "sources": sources, "fixture_id": FIXTURE_ID, "fixture_hash": FIXTURE_HASH}
    result["receipt"] = {"id": digest(result), "created_at": datetime.now(timezone.utc).isoformat(),
                         "qualification": "Read-only synthetic computation. No preference profile or external action was saved."}
    return result
