"""Pin the cached Lambda SDK closure before accepting an injected AWS client.

Verifies installed public code, not caller authorization, credentials or network.
No SDK client creation, credential discovery or service call happens here.
"""
import hashlib
import importlib
import importlib.metadata
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent
SDK_ROOT = Path('/var/lang')
SITE = SDK_ROOT / 'lib/python3.12/site-packages'
_VERIFIED = False


class SDKRefusal(ValueError):
    pass


def verify_sdk():
    global _VERIFIED
    if _VERIFIED:
        return
    if sys.platform != 'linux' or sys.version_info[:2] != (3, 12):
        raise SDKRefusal('Only the pinned Linux Python3.12 SDK environment is supported.')
    manifest = json.loads((ROOT / 'SDK_CLOSURE.json').read_bytes())
    if manifest.get('schema') != 'cached-image-sdk-closure-v1':
        raise SDKRefusal('SDK closure schema differs.')
    roots = {'boto3', 'botocore', 'urllib3', 'jmespath', 'dateutil', 's3transfer', 'six'}
    for name, module in tuple(sys.modules.items()):
        if name.split('.')[0] in roots and getattr(module, '__file__', None):
            if not Path(module.__file__).resolve().is_relative_to(SITE):
                raise SDKRefusal('Preloaded SDK module came from another origin.')
    for name, proof in manifest['distributions'].items():
        if proof.get('installed') is not True or not proof.get('files'):
            raise SDKRefusal('A required pinned SDK distribution is absent.')
        for file in proof['files']:
            relative = file['path']
            if ('\\' in relative or ':' in relative or relative.startswith('/')
                    or any(part in {'', '.', '..'} for part in relative.split('/'))):
                raise SDKRefusal('Invalid SDK manifest path.')
            target = SDK_ROOT / relative
            # Distribution metadata includes its exact pinned public CLI script
            # /var/lang/bin/jp.py. Verify declared files within SDK_ROOT, while
            # all imported modules must still originate from fixed SITE.
            if (target.is_symlink() or not target.resolve().is_relative_to(SDK_ROOT)
                    or not target.is_file() or target.stat().st_size != file['bytes']
                    or hashlib.sha256(target.read_bytes()).hexdigest() != file['sha256']):
                raise SDKRefusal('Installed SDK source or metadata differs.')
    if str(SITE) not in sys.path:
        sys.path.append(str(SITE))
    for name, proof in manifest['distributions'].items():
        distribution = importlib.metadata.distribution(name)
        if (distribution.version != proof['version']
                or not Path(distribution.locate_file('')).resolve().is_relative_to(SITE)):
            raise SDKRefusal('SDK distribution version or origin differs.')
    for name in roots:
        module = importlib.import_module(name)
        if not Path(module.__file__).resolve().is_relative_to(SITE):
            raise SDKRefusal('Loaded SDK source origin differs.')
    _VERIFIED = True


def validate_client(client):
    verify_sdk()
    from botocore.client import BaseClient
    import botocore.client
    expected = SITE / 'botocore/client.py'
    if (Path(botocore.client.__file__).resolve() != expected
            or not isinstance(client, BaseClient)
            or type(client).__module__ != 'botocore.client'
            or getattr(getattr(client, 'meta', None), 'service_model', None) is None
            or client.meta.service_model.service_name != 'dynamodb'):
        raise SDKRefusal('An actual pinned DynamoDB SDK client is required.')
    return client
