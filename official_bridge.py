"""Private pinned direct-factory IPC. No HTTP or credential implementation exists here."""
import hashlib
import json
from pathlib import Path
import sys

from bridge import OfflineProcessBridge, BridgeError

HERE=Path(__file__).resolve().parent
LOCK=HERE/'OFFICIAL_SOURCE_LOCK.json'
CHILD=HERE/'official_factory_child.mjs'

class OfficialFactoryOfflineBridge(OfflineProcessBridge):
    """Caller supplies a reviewed executable and pins; raw transport remains injected.

    Only offline fake transport has been qualified. This neither grants live-call
    authority nor proves an OS network sandbox. Use one fresh process per operation.
    """
    def __init__(self, *, node_executable, node_sha256, child_sha256, lock_sha256, forbidden_fragments=()):
        super().__init__(fixture_sha256='0'*64, forbidden_fragments=forbidden_fragments)
        self.node=Path(node_executable).resolve()
        self.node_sha256=node_sha256
        self.child_sha256=child_sha256
        self.lock_sha256=lock_sha256

    def _launch_command(self):
        for path,pin in [(self.node,self.node_sha256),(CHILD,self.child_sha256),(LOCK,self.lock_sha256)]:
            if not path.is_absolute() or path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest()!=pin:
                raise ValueError()
        lock=json.loads(LOCK.read_text(encoding='utf-8'))
        if lock['harnessVersion']!='0.1.26' or lock['typeboxVersion']!='1.3.7': raise ValueError()
        for relative,pin in lock['sources'].items():
            path=(HERE/relative).resolve()
            if not path.is_relative_to(HERE) or path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest()!=pin:
                raise ValueError()
        return [str(self.node),'--permission','--allow-fs-read='+str(HERE),str(CHILD),self.lock_sha256]

    def _launch_environment(self):
        # Fixed nonsecret Windows runtime location, not inherited provider/config state.
        return {'SystemRoot':r'C:\Windows'} if sys.platform=='win32' else {}

    async def run_vendor(self,*args,**kwargs):
        raise BridgeError('Live vendor operation is not enabled; only explicit offline qualification is supported.')
