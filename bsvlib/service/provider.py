from abc import ABCMeta, abstractmethod
from typing import List, Dict, Optional, Tuple, Union

import requests

from ..constants import Chain, HTTP_REQUEST_TIMEOUT
from ..keys import PublicKey, PrivateKey


class Provider(metaclass=ABCMeta):

    def __init__(self, chain: Chain = Chain.MAIN, headers: Optional[Dict] = None, timeout: Optional[int] = None):
        self.chain: Chain = chain
        self.headers: Dict = headers or {'Content-Type': 'application/json', 'Accept': 'application/json', }
        self.timeout: int = timeout or HTTP_REQUEST_TIMEOUT

    def parse_kwargs(self, **kwargs) -> Tuple[Optional[str], Optional[PublicKey], Optional[PrivateKey]]:
        """
        try to parse out (address, public_key, private_key) from kwargs
        """
        private_key: PrivateKey = kwargs.get('private_keys')[0] if kwargs.get('private_keys') else None
        public_key: PublicKey = kwargs.get('public_key') or (private_key.public_key() if private_key else None)
        address: str = kwargs.get('address') or (public_key.address(chain=self.chain) if public_key else None)
        return address, public_key, private_key

    def get(self, **kwargs) -> Union[Dict, List[Dict]]:
        """
        HTTP GET wrapper
        """
        r = requests.get(kwargs['url'], headers=self.headers, params=kwargs.get('params'), timeout=self.timeout)
        r.raise_for_status()
        return r.json()

    @abstractmethod
    def get_unspents(self, **kwargs) -> List[Dict]:
        """kwargs will pass the following at least
        {
            'private_keys': List[bsvlib.keys.PrivateKey],
        }
        :returns: unspents in dict format refers to bsvlib.transaction.unspent.Unspent
        """
        raise NotImplementedError('Provider.get_unspents')

    @abstractmethod
    def get_balance(self, **kwargs) -> int:
        """kwargs will pass the following at least
        {
            'private_keys': List[bsvlib.keys.PrivateKey],
        }
        :returns: balance in satoshi
        """
        raise NotImplementedError('Provider.get_balance')

    @abstractmethod
    def broadcast(self, raw: str) -> Optional[str]:
        """
        :returns: txid if broadcast successfully otherwise None
        """
        raise NotImplementedError('Provider.broadcast')
