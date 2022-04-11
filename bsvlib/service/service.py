from typing import List, Dict, Optional

from .metasv import MetaSV
from .provider import Provider, BroadcastResult
from .whatsonchain import WhatsOnChain
from ..constants import Chain, METASV_TOKEN


class Service:

    def __init__(self, chain: Optional[Chain] = None, provider: Optional[Provider] = None):
        chain = chain or Chain.MAIN
        default_provider = MetaSV(token=METASV_TOKEN) if chain == Chain.MAIN and METASV_TOKEN else WhatsOnChain(chain)
        self.provider = provider or default_provider
        self.chain = self.provider.chain

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

    def broadcast(self, raw: str) -> BroadcastResult:
        """
        :returns: (True, txid) or (False, error_message)
        """
        return self.provider.broadcast(raw)  # pragma: no cover
