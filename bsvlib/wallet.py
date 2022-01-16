from concurrent.futures import ThreadPoolExecutor
from itertools import repeat
from typing import Optional, List, Tuple, Union, Dict, Any

from .constants import Chain, THREAD_POOL_MAX_EXECUTORS
from .keys import PrivateKey
from .service.provider import Provider
from .service.service import Service
from .transaction.transaction import Transaction, TxOutput, InsufficientFundsError
from .transaction.unspent import Unspent


def get_unspents_wrapper(d: Dict) -> List['Unspent']:
    return Unspent.get_unspents(**d)


def get_balance_wrapper(chain: Chain, provider: Provider, d: Dict) -> int:
    return Service(chain, provider).get_balance(**d)


class Wallet:
    def __init__(self, keys: Optional[List[Union[str, int, bytes, PrivateKey]]] = None, chain: Chain = Chain.MAIN, provider: Optional[Provider] = None, **kwargs):
        """
        create an empty wallet if keys is None
        """
        self.chain: Chain = chain
        self.provider: Provider = provider
        self.keys: List[PrivateKey] = []
        if keys:
            self.add_keys(keys)
        self.unspents: List[Unspent] = []
        self.kwargs: Dict[str, Any] = dict(**kwargs) or {}

    def add_key(self, key: Union[str, int, bytes, PrivateKey, None] = None) -> 'Wallet':
        """
        random a new private key then add to wallet if key is None
        """
        private_key = key if isinstance(key, PrivateKey) else PrivateKey(key)
        private_key.chain = self.chain
        self.keys.append(private_key)
        return self

    def add_keys(self, keys: List[Union[str, int, bytes, PrivateKey]]) -> 'Wallet':
        for key in keys:
            self.add_key(key)
        return self

    def get_keys(self) -> List[PrivateKey]:
        return self.keys

    def get_unspents(self, refresh: bool = False, **kwargs) -> List[Unspent]:
        if refresh:
            self.unspents = []
            with ThreadPoolExecutor(max_workers=THREAD_POOL_MAX_EXECUTORS) as executor:
                args = [dict(chain=self.chain, provider=self.provider, private_keys=[key], **self.kwargs, **kwargs) for key in self.keys]
                for r in executor.map(get_unspents_wrapper, args):
                    self.unspents.extend(r)
        return self.unspents

    def get_balance(self, refresh: bool = False, **kwargs) -> int:
        if refresh:
            with ThreadPoolExecutor(max_workers=THREAD_POOL_MAX_EXECUTORS) as executor:
                args = [dict(private_keys=[key], **self.kwargs, **kwargs) for key in self.keys]
                return sum([r for r in executor.map(get_balance_wrapper, repeat(self.chain), repeat(self.provider), args)])
        return sum([unspent.satoshi for unspent in self.unspents])

    def create_transaction(self, outputs: Optional[List[Tuple]] = None, leftover: Optional[str] = None,
                           fee_rate: Optional[float] = None, unspents: Optional[List[Unspent]] = None,
                           combine: bool = False, pushdatas: Optional[List[Union[str, bytes]]] = None,
                           change: bool = True, sign: bool = True, **kwargs) -> Transaction:  # pragma: no cover
        """create a signed transaction
        :param outputs: list of tuple (address, satoshi). if None then sweep all the unspents to leftover
        :param leftover: transaction change address
        :param fee_rate: 0.5 satoshi per byte if None
        :param unspents: list of unspents, will refresh from service if None
        :param combine: use all available unspents if True
        :param pushdatas: list of OP_RETURN pushdata
        :param change: automatically add a P2PKH change output if True
        :param sign: sign the transaction if True
        :param kwargs: passing to get unspents and sign
        """
        self.unspents = unspents or self.get_unspents(refresh=True, **self.kwargs, **kwargs)
        if not self.unspents:
            raise InsufficientFundsError('transaction mush have at least one unspent')

        t = Transaction(fee_rate=fee_rate, chain=self.chain, provider=self.provider)
        if pushdatas:
            t.add_output(TxOutput(pushdatas))
        if outputs:
            t.add_outputs([TxOutput(output[0], output[1]) for output in outputs])
        # pick unspent
        picked_unspents = []
        if combine or not outputs:
            picked_unspents = self.unspents
            self.unspents = []
            t.add_inputs([unspent for unspent in picked_unspents])
        else:
            unspent = self.unspents.pop(0)
            picked_unspents.append(unspent)
            t.add_input(unspent)
            while t.fee() < t.estimated_fee() and self.unspents:
                unspent = self.unspents.pop(0)
                picked_unspents.append(unspent)
                t.add_input(unspent)
        if t.fee() < t.estimated_fee():
            self.unspents.extend(picked_unspents)
            raise InsufficientFundsError(f'require {t.estimated_fee() + t.satoshi_total_out()} satoshi but only {t.satoshi_total_in()}')
        if change:
            t.add_change(leftover)
        if sign:
            t.sign(**self.kwargs, **kwargs)
        return t

    def send_transaction(self, outputs: Optional[List[Tuple]] = None, leftover: Optional[str] = None,
                         fee_rate: Optional[float] = None, unspents: Optional[List[Unspent]] = None,
                         combine: bool = False, pushdatas: Optional[List[Union[str, bytes]]] = None,
                         **kwargs) -> Optional[str]:  # pragma: no cover
        """send a transaction
        :param outputs: list of tuple (address, satoshi). if None then sweep all the unspents to leftover
        :param leftover: transaction change address
        :param fee_rate: 0.5 satoshi per byte if None
        :param unspents: list of unspents, will refresh from service if None
        :param combine: use all available unspents if True
        :param pushdatas: list of OP_RETURN pushdata
        :param kwargs: passing to get unspents and sign
        :returns: txid if successfully otherwise None
        """
        return self.create_transaction(outputs, leftover, fee_rate, unspents, combine, pushdatas, True, True, **kwargs).broadcast()
