from abc import ABCMeta, abstractmethod
from typing import List, Dict, Optional


class Provider(metaclass=ABCMeta):

    @abstractmethod
    def get_unspents(self, **kwargs) -> List[Dict]:
        """
        :returns: unspents in dict refers to `bsvlib.transaction.unspent.Unspent`
        """
        raise NotImplementedError('Provider.get_unspents')

    @abstractmethod
    def get_balance(self, **kwargs) -> int:
        """
        :returns: balance in satoshi
        """
        raise NotImplementedError('Provider.get_balance')

    @abstractmethod
    def broadcast(self, raw: str) -> Optional[str]:
        """
        :returns: txid if broadcast successfully otherwise None
        """
        raise NotImplementedError('Provider.broadcast')