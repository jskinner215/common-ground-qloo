"""One recommendation operation per exact reviewed resolution, before transport.

Existing compact records and transaction sizes stay unchanged. A fresh caller
ID cannot bypass an earlier pending/uncertain recommendation or failed review
invalidation. A completed identical pair replays its existing source receipt;
different pairs need a new resolution instead of a new provider attempt.
"""
from contextvars import ContextVar

from compact_confirmation import CompactConfirmationStore
from confirmation_store import request_key, fingerprint
from harness_contract import QlooHarnessContractAdapter
from workflow import WorkflowError

_RECOMMEND = ContextVar("qloo_reviewed_recommendation", default=None)


class FencedCompactStore(CompactConfirmationStore):
    @staticmethod
    def _operation_sk(key, kind, request_id):
        request_key(request_id)
        if kind == "recommend":
            binding = _RECOMMEND.get()
            if not isinstance(binding, dict) or binding.get("request_id") != request_id:
                raise WorkflowError("review_binding_required", "Use this exact reviewed recommendation operation.", 409)
            # Resolution ID binds exact session, generation, names, choices and
            # source receipts. Its pending operation is unique for that whole
            # review, regardless of fresh caller operation IDs.
            request_id = "review:" + fingerprint(binding.get("resolution_id"))
        return CompactConfirmationStore._operation_sk(key, kind, request_id)


class FencedHarnessAdapter(QlooHarnessContractAdapter):
    async def recommend_pair(self, queries, resolution_id, selected_ids, *, session_id, request_id):
        token = _RECOMMEND.set({"request_id": request_key(request_id),
                                "resolution_id": fingerprint(resolution_id)})
        try:
            return await super().recommend_pair(queries, resolution_id, selected_ids,
                session_id=session_id, request_id=request_id)
        finally:
            _RECOMMEND.reset(token)

    def recover_known_recommendation(self, queries, resolution_id, selected_ids, *, session_id, request_id, deadline=None):
        token = _RECOMMEND.set({"request_id": request_key(request_id), "resolution_id": fingerprint(resolution_id)})
        try:
            return super().recover_known_recommendation(queries, resolution_id, selected_ids,
                session_id=session_id, request_id=request_id, deadline=deadline)
        finally:
            _RECOMMEND.reset(token)
