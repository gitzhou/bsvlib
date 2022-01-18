import json
from contextlib import suppress
from typing import Optional, List, Dict

import requests

from .provider import Provider
from ..constants import HTTP_REQUEST_TIMEOUT
from ..keys import PublicKey
from ..script.type import P2pkScriptType


class SensibleQuery(Provider):

    def __init__(self):
        self.url: str = 'https://api.sensiblequery.com'
        self.headers: Dict = {'Content-Type': 'application/json', 'Accept': 'application/json', }
        self.timeout: int = HTTP_REQUEST_TIMEOUT

    def get(self, **kwargs) -> Dict:
        r = requests.get(kwargs['url'], headers=self.headers, params=kwargs.get('params'), timeout=self.timeout)
        r.raise_for_status()
        return r.json()['data']

    def get_unspents(self, **kwargs) -> List[Dict]:
        """
        P2PKH and P2PK unspents
        """
        with suppress(Exception):
            public_key: PublicKey = kwargs.get('public_key') or kwargs.get('private_keys')[0].public_key()
            address: str = kwargs.get('address') or public_key.address()
            r: Dict = self.get(url=f'{self.url}/address/{address}/utxo', params={'cursor': 0, 'size': 5120})
            unspents: List[Dict] = []
            for item in r:
                unspent = {'txid': item['txid'], 'vout': item['vout'], 'satoshi': item['satoshi'], 'height': item['height']}
                if item['scriptType'] in ['21ac', '41ac']:  # pragma: no cover
                    # P2PK requires public key to set locking script
                    if not public_key:
                        continue
                    unspent['script_type'] = P2pkScriptType()
                    unspent['locking_script'] = P2pkScriptType.locking(public_key.serialize())
                unspent.update(kwargs)
                unspents.append(unspent)
            return unspents
        return []  # pragma: no cover

    def get_balance(self, **kwargs) -> int:
        with suppress(Exception):
            public_key: PublicKey = kwargs.get('public_key') or kwargs.get('private_keys')[0].public_key()
            address: str = kwargs.get('address') or public_key.address()
            r: Dict = self.get(url=f'{self.url}/address/{address}/balance')
            return r.get('satoshi') + r.get('pendingSatoshi')
        return 0  # pragma: no cover

    def broadcast(self, raw: str) -> Optional[str]:  # pragma: no cover
        with suppress(Exception):
            data = json.dumps({'txHex': raw})
            r = requests.post(f'{self.url}/pushtx', headers=self.headers, data=data, timeout=self.timeout)
            r.raise_for_status()
            return r.json()['data']
        return None
