from typing import List, Dict, Optional

from .metasv import MetaSV
from .provider import Provider
from .whatsonchain import WhatsOnChain
from ..constants import Chain, METASV_TOKEN


class Service:

    def __init__(self, chain: Chain = Chain.MAIN, provider: Optional[Provider] = None):
        self.chain: Chain = chain
        default_provider = MetaSV(METASV_TOKEN) if chain == Chain.MAIN and METASV_TOKEN else WhatsOnChain(self.chain)
        self.provider = provider or default_provider

    def get_unspents(self, **kwargs) -> List[Dict]:
        """kwargs will pass the following at least
        {
            'private_keys': List[bsvlib.keys.PrivateKey],
        }
        :returns: unspents in dict format refers to bsvlib.transaction.unspent.Unspent
        """
        return self.provider.get_unspents(**kwargs)

    def get_balance(self, **kwargs) -> int:
        """kwargs will pass the following at least
        {
            'private_keys': List[bsvlib.keys.PrivateKey],
        }
        :returns: balance in satoshi
        """
        return self.provider.get_balance(**kwargs)

    def broadcast(self, raw: str) -> Optional[str]:
        """
        :returns: txid if broadcast successfully otherwise None
        """
        return self.provider.broadcast(raw)  # pragma: no cover
