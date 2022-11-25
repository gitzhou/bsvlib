import json
from typing import List, Dict, Optional

import requests

from .provider import Provider, BroadcastResult
from ..constants import Chain


class WhatsOnChain(Provider):  # pragma: no cover

    def __init__(self, chain: Chain = Chain.MAIN, headers: Optional[Dict] = None, timeout: Optional[int] = None):
        super().__init__(chain, headers, timeout)
        self.url: str = 'https://api.whatsonchain.com/v1/bsv'

    def get_unspents(self, **kwargs) -> List[Dict]:
        try:
            address, _, _ = self.parse_kwargs(**kwargs)
            r: Dict = self.get(url=f'{self.url}/{self.chain}/address/{address}/unspent')
            unspents: List[Dict] = []
            for item in r:  # pragma: no cover
                unspent = {'txid': item['tx_hash'], 'vout': item['tx_pos'], 'satoshi': item['value'], 'height': item['height']}
                unspent.update(kwargs)
                unspents.append(unspent)
            return unspents
        except Exception as e:
            if kwargs.get('throw'):
                raise e
        return []

    def get_balance(self, **kwargs) -> int:
        try:
            address, _, _ = self.parse_kwargs(**kwargs)
            r: Dict = self.get(url=f'{self.url}/{self.chain}/address/{address}/balance')
            return r.get('confirmed') + r.get('unconfirmed')
        except Exception as e:
            if kwargs.get('throw'):
                raise e
        return 0

    def broadcast(self, raw: str) -> BroadcastResult:
        propagated, message = False, ''
        try:
            data = json.dumps({'txHex': raw})
            r = requests.post(f'{self.url}/{self.chain}/tx/raw', headers=self.headers, data=data, timeout=self.timeout)
            message = r.json()
            r.raise_for_status()
            propagated = True
        except Exception as e:
            message = message or str(e)
        return BroadcastResult(propagated, message)
