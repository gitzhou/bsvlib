from typing import List, Dict, Optional


class Provider:
    def get_unspents(self, address: str) -> List[Dict]:
        """
        :returns: unspents in dict refers to `bsvlib.transaction.unspent.Unspent`
        """
        raise NotImplementedError('Provider.get_unspents')

    def get_balance(self, address: str) -> int:
        """
        :returns: balance in satoshi
        """
        raise NotImplementedError('Provider.get_balance')

    def broadcast(self, raw: str) -> Optional[str]:
        """
        :returns: txid if broadcast successfully otherwise None
        """
        raise NotImplementedError('Provider.broadcast')
