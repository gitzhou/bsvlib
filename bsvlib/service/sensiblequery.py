import json
from contextlib import suppress
from typing import Optional, List, Dict

import requests

from .provider import Provider
from ..constants import Chain
from ..script.type import P2pkScriptType


class SensibleQuery(Provider):

    def __init__(self, chain: Chain = Chain.MAIN, headers: Optional[Dict] = None, timeout: Optional[int] = None):
        super().__init__(chain, headers, timeout)
        self.url: str = 'https://api.sensiblequery.com' + ('' if chain == Chain.MAIN else '/test')

    def get_unspents(self, **kwargs) -> List[Dict]:
        """
        P2PKH and P2PK unspents
        """
        with suppress(Exception):
            address, public_key, _ = self.parse_kwargs(**kwargs)
            #
            # ATTENTION
            #   it is not recommended to use paginated queries on this API, and up to 5120 records are supported
            #
            r: Dict = self.get(url=f'{self.url}/address/{address}/utxo', params={'cursor': 0, 'size': 5120})['data']
            unspents: List[Dict] = []
            for item in r:  # pragma: no cover
                unspent = {'txid': item['txid'], 'vout': item['vout'], 'satoshi': item['satoshi'], 'height': item['height']}
                if item['scriptType'] in ['21ac', '41ac'] and public_key:
                    # P2PK requires public key to set locking script
                    unspent['script_type'] = P2pkScriptType()
                    unspent['locking_script'] = P2pkScriptType.locking(public_key.serialize())
                unspent.update(kwargs)
                unspents.append(unspent)
            return unspents
        return []  # pragma: no cover

    def get_balance(self, **kwargs) -> int:
        with suppress(Exception):
            address, _, _ = self.parse_kwargs(**kwargs)
            r: Dict = self.get(url=f'{self.url}/address/{address}/balance')['data']
            return r.get('satoshi') + r.get('pendingSatoshi')
        return 0  # pragma: no cover

    def broadcast(self, raw: str) -> Optional[str]:  # pragma: no cover
        with suppress(Exception):
            data = json.dumps({'txHex': raw})
            r = requests.post(f'{self.url}/pushtx', headers=self.headers, data=data, timeout=self.timeout)
            r.raise_for_status()
            return r.json()['data']
        return None
