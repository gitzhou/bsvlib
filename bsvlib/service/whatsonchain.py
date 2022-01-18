import json
from contextlib import suppress
from typing import List, Dict, Optional

import requests

from .provider import Provider
from ..constants import Chain, HTTP_REQUEST_TIMEOUT
from ..keys import PublicKey


class WhatsOnChain(Provider):

    def __init__(self, chain: Chain = Chain.MAIN):
        self.chain: Chain = chain
        self.url: str = 'https://api.whatsonchain.com/v1/bsv'
        self.headers: Dict = {'Content-Type': 'application/json', 'Accept': 'application/json', }
        self.timeout: int = HTTP_REQUEST_TIMEOUT

    def get(self, **kwargs) -> Dict:
        r = requests.get(kwargs['url'], headers=self.headers, params=kwargs.get('params'), timeout=self.timeout)
        r.raise_for_status()
        return r.json()

    def parse_address(self, **kwargs) -> str:
        public_key: PublicKey = kwargs.get('public_key') or kwargs.get('private_keys')[0].public_key()
        return kwargs.get('address') or public_key.address(chain=self.chain)

    def get_unspents(self, **kwargs) -> List[Dict]:
        """
        only P2PKH unspents
        """
        with suppress(Exception):
            address: str = self.parse_address(**kwargs)
            r: Dict = self.get(url=f'{self.url}/{self.chain}/address/{address}/unspent')
            unspents: List[Dict] = []
            for item in r:
                unspent = {'txid': item['tx_hash'], 'vout': item['tx_pos'], 'satoshi': item['value'], 'height': item['height']}
                unspent.update(kwargs)
                unspents.append(unspent)
            return unspents
        return []  # pragma: no cover

    def get_balance(self, **kwargs) -> int:
        with suppress(Exception):
            address: str = self.parse_address(**kwargs)
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
