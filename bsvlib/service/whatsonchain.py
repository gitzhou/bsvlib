import json
from contextlib import suppress
from typing import List, Dict, Optional

import requests

from .provider import Provider
from ..constants import Chain


class WhatsOnChain(Provider):

    def __init__(self, chain: Chain = Chain.MAIN):
        self.chain: Chain = chain
        self.url: str = 'https://api.whatsonchain.com/v1/bsv'
        self.headers: Dict = {'Content-Type': 'application/json', 'Accept': 'application/json', }
        self.timeout: int = 30

    def get_unspents(self, address: str) -> List[Dict]:
        with suppress(Exception):
            r = requests.get(f'{self.url}/{self.chain}/address/{address}/unspent', headers=self.headers, timeout=self.timeout)
            r.raise_for_status()
            unspents: Dict = r.json()
            return [{'txid': unspent['tx_hash'], 'vout': unspent['tx_pos'], 'satoshi': unspent['value'], 'height': unspent['height'], 'address': address} for unspent in unspents]
        return []

    def get_balance(self, address: str) -> int:
        with suppress(Exception):
            r = requests.get(f'{self.url}/{self.chain}/address/{address}/balance', headers=self.headers, timeout=self.timeout)
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
