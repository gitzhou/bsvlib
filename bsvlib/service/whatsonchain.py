import json
from contextlib import suppress
from typing import List, Dict, Optional

import requests

from .provider import Provider
from ..constants import Chain, HTTP_REQUEST_TIMEOUT
from ..keys import PrivateKey


class WhatsOnChain(Provider):

    def __init__(self, chain: Chain = Chain.MAIN):
        self.chain: Chain = chain
        self.url: str = 'https://api.whatsonchain.com/v1/bsv'
        self.headers: Dict = {'Content-Type': 'application/json', 'Accept': 'application/json', }
        self.timeout: int = HTTP_REQUEST_TIMEOUT

    def get_unspents(self, **kwargs) -> List[Dict]:
        """
        only P2PKH unspents
        """
        with suppress(Exception):
            private_key: PrivateKey = kwargs.get('private_keys')[0]
            r = requests.get(f'{self.url}/{self.chain}/address/{private_key.address()}/unspent', headers=self.headers, timeout=self.timeout)
            r.raise_for_status()
            unspents: List[Dict] = []
            for item in r.json():
                unspent = {'txid': item['tx_hash'], 'vout': item['tx_pos'], 'satoshi': item['value'], 'height': item['height']}
                unspent.update(kwargs)
                unspents.append(unspent)
            return unspents
        return []

    def get_balance(self, **kwargs) -> int:
        with suppress(Exception):
            private_key: PrivateKey = kwargs.get('private_keys')[0]
            r = requests.get(f'{self.url}/{self.chain}/address/{private_key.address()}/balance', headers=self.headers, timeout=self.timeout)
            r.raise_for_status()
            balance: dict = r.json()
            return balance.get('confirmed') + balance.get('unconfirmed')
        return 0

    def broadcast(self, raw: str) -> Optional[str]:
        with suppress(Exception):
            data = json.dumps({'txHex': raw})
            r = requests.post(f'{self.url}/{self.chain}/tx/raw', headers=self.headers, data=data, timeout=self.timeout)
            r.raise_for_status()
            return r.json()
        return None
