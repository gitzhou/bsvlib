from typing import List, Dict, Optional

from .whatsonchain import WhatsOnChain
from ..constants import Chain


class Service:
    def __init__(self, chain: Chain = Chain.MAIN):
        self.chain = chain
        self.api = WhatsOnChain(chain)

    def get_unspents(self, address: str) -> List[Dict]:
        return self.api.get_unspents(address)

    def get_balance(self, address: str) -> int:
        return self.api.get_balance(address)

    def broadcast(self, raw: str) -> Optional[str]:
        """
        returns txid if broadcast successfully otherwise None
        """
        return self.api.broadcast(raw)
