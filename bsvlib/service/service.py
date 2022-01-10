from typing import List, Dict, Optional

from .provider import Provider
from .whatsonchain import WhatsOnChain
from ..constants import Chain


class Service:

    def __init__(self, chain: Chain = Chain.MAIN, provider: Optional[Provider] = None):
        self.chain: Chain = chain
        self.provider = provider or WhatsOnChain(self.chain)

    def get_unspents(self, address: str) -> List[Dict]:
        """
        :returns: unspents in dict refers to `bsvlib.transaction.unspent.Unspent`
        """
        return self.provider.get_unspents(address)

    def get_balance(self, address: str) -> int:
        """
        :returns: balance in satoshi
        """
        return self.provider.get_balance(address)

    def broadcast(self, raw: str) -> Optional[str]:
        """
        :returns: txid if broadcast successfully otherwise None
        """
        return self.provider.broadcast(raw)
