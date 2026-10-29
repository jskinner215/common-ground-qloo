"""Qloo request-scoped pacing/transaction admission; shared quota stays unchanged."""
import math
import time

from global_quota_v2 import DynamoQuotaStore, QuotaError

TRANSACTION_MARGIN_SECONDS=0.25
RESPONSE_MARGIN_SECONDS=0.25


class DeadlineQuotaStore(DynamoQuotaStore):
    """Preserve2s pacing/CAS/history while refusing anticipated late mutations.

    The injected durable client/waiter must still honor its own bounded I/O.
    This cannot interrupt an uncooperative synchronous SDK or reverse a commit.
    """
    def __init__(self,client,*,table_name,policy,clock_ms,request_binding):
        super().__init__(client,table_name=table_name,policy=policy,clock_ms=clock_ms)
        if not callable(request_binding):raise ValueError('Explicit current-request context required')
        self._request_binding=request_binding

    def _before(self,delay=0):
        binding=self._request_binding()
        deadline=binding.get('deadline') if isinstance(binding,dict) else None
        work=binding.get('work_deadline',deadline) if isinstance(binding,dict) else None
        if type(work) not in (int,float) or not math.isfinite(work):
            raise QuotaError('qloo_deadline_before_mutation','A finite trusted work deadline is required; no mutation started.',504)
        if type(deadline) in (int,float) and math.isfinite(deadline):deadline=min(deadline,work)
        if (type(deadline) not in (int,float) or not math.isfinite(deadline)
                or type(delay) not in (int,float) or not math.isfinite(delay) or delay<0
                or deadline-time.monotonic()<delay+TRANSACTION_MARGIN_SECONDS+RESPONSE_MARGIN_SECONDS):
            raise QuotaError('qloo_deadline_before_mutation',
                'The existing operation deadline cannot cover pacing, transaction and response; no mutation started.',504)

    def _commit(self,changes):
        self._before()
        validator=getattr(self.client,'validate_transaction',None)
        if callable(validator):validator(changes)
        return super()._commit(changes)

    def guarded_transact(self,changes,now_ms=None,*,waiter=None):
        self._before()
        bounded=None
        deadline_failure=[]
        if waiter is not None:
            if not callable(waiter):raise ValueError('An explicit waiter must be callable')
            def checked(delay=0):
                try:
                    self._before(delay)
                except QuotaError as error:
                    deadline_failure.append(error)
                    raise
            def bounded(delay):
                checked(delay)
                waiter(delay)
                checked()
        try:
            return super().guarded_transact(changes,now_ms=now_ms,waiter=bounded)
        except QuotaError:
            # The shared gate sanitizes arbitrary waiter failures as quota_paced.
            # Preserve only this helper's own safe deadline classification.
            if deadline_failure:
                raise deadline_failure[0] from None
            raise
