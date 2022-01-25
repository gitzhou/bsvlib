import json
from contextlib import suppress
from typing import List, Dict, Optional

import requests

from .provider import Provider
from ..constants import Chain


class WhatsOnChain(Provider):

    def __init__(self, chain: Chain = Chain.MAIN, headers: Optional[Dict] = None, timeout: Optional[int] = None):
        super().__init__(chain, headers, timeout)
        self.url: str = 'https://api.whatsonchain.com/v1/bsv'

    def get_unspents(self, **kwargs) -> List[Dict]:
        """
        only P2PKH unspents
        """
        with suppress(Exception):
            address, _, _ = self.parse_kwargs(**kwargs)
            r: Dict = self.get(url=f'{self.url}/{self.chain}/address/{address}/unspent')
            unspents: List[Dict] = []
            for item in r:  # pragma: no cover
                unspent = {'txid': item['tx_hash'], 'vout': item['tx_pos'], 'satoshi': item['value'], 'height': item['height']}
                unspent.update(kwargs)
                unspents.append(unspent)
            return unspents
        return []  # pragma: no cover

    def get_balance(self, **kwargs) -> int:
        with suppress(Exception):
            address, _, _ = self.parse_kwargs(**kwargs)
            r: Dict = self.get(url=f'{self.url}/{self.chain}/address/{address}/balance')
            return r.get('confirmed') + r.get('unconfirmed')
        return 0  # pragma: no cover

    def broadcast(self, raw: str) -> Optional[str]:  # pragma: no cover
        with suppress(Exception):
            data = json.dumps({'txHex': raw})
            r = requests.post(f'{self.url}/{self.chain}/tx/raw', headers=self.headers, data=data, timeout=self.timeout)
            r.raise_for_status()
            return r.json()
        return None
