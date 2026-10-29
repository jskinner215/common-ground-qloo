"""Existing Qloo history guard; static mutation refusal is known not executed."""
from global_quota_v2 import QuotaError


class ControlUnavailable(RuntimeError):
    pass


class ControlMutationRefused(QuotaError):
    """Only this guard's local pre-client validation raises this classification."""
    execution_state='known_not_executed'
    def __init__(self):
        super().__init__('control_guard_not_executed',
            'The local control guard refused before the durable client was called; no transaction started.',503)


class ExistingControlClient:
    """No SDK/init/reset. Unknown underlying client outcomes remain unknown.

    DeadlineQuotaStore must call validate_transaction BEFORE its shared _commit
    error sanitizer. The transaction method repeats the same pure check; it does
    not reinterpret exceptions from the underlying client as local refusals.
    """
    def __init__(self,client,table_name):
        if not all(callable(getattr(client,n,None)) for n in ('get_item','transact_write_items')):
            raise ControlUnavailable('Explicit compatible durable client required.')
        self._client,self._table=client,table_name

    @staticmethod
    def _control(key):
        return isinstance(key,dict) and key.get('PK')=={'S':'qloo'} and key.get('SK')=={'S':'quota#v2#control'}

    def get_item(self,**kwargs):
        if kwargs.get('TableName')!=self._table:
            raise ControlUnavailable('Unexpected table refused.')
        control=self._control(kwargs.get('Key'))
        if control and kwargs.get('ConsistentRead') is not True:
            raise ControlUnavailable('A strong existing-control read is required.')
        result=self._client.get_item(**kwargs)
        if control and (not isinstance(result,dict) or result.get('Item') is None):
            raise ControlUnavailable('Quota history is absent or unknown; initialization is not authorized.')
        return result

    def validate_transaction(self,items):
        """Pure local preflight; it performs no client access or mutation."""
        if not isinstance(items,list) or not items:raise ControlMutationRefused()
        for item in items:
            if not isinstance(item,dict) or len(item)!=1:raise ControlMutationRefused()
            operation=next(iter(item.values()))
            if not isinstance(operation,dict) or operation.get('TableName')!=self._table:raise ControlMutationRefused()
            if self._control(operation.get('Key')) and set(item)&{'Update','Delete'}:raise ControlMutationRefused()
            put=item.get('Put')
            if put and self._control(put.get('Item')):
                if (put.get('ConditionExpression')!='#revision = :revision'
                        or put.get('ExpressionAttributeNames')!={'#revision':'revision'}
                        or set(put.get('ExpressionAttributeValues',{}))!={':revision'}):raise ControlMutationRefused()
        # Nested copies of this same guard remain pure and need no extra I/O.
        if isinstance(self._client,ExistingControlClient):self._client.validate_transaction(items)

    def transact_write_items(self,**kwargs):
        self.validate_transaction(kwargs.get('TransactItems'))
        return self._client.transact_write_items(**kwargs)
