from typing import Optional, List, Tuple, Union

from .constants import Chain
from .keys import PrivateKey
from .service.provider import Provider
from .transaction.transaction import Transaction, TxInput, TxOutput
from .transaction.unspent import Unspent


class InsufficientFundsError(ValueError):
    pass


class Wallet:
    def __init__(self, keys: Optional[List[Union[str, int, bytes, PrivateKey]]] = None, chain: Chain = Chain.MAIN, provider: Optional[Provider] = None):
        """
        create an empty wallet if keys is None
        """
        self.keys: List[PrivateKey] = []
        if keys:
            self.add_keys(keys)
        self.chain: Chain = chain
        self.provider: Provider = provider
        self.unspents: List[Unspent] = []

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

    def get_unspents(self, refresh: bool = False) -> List[Unspent]:
        if refresh:
            self.unspents = []
            for key in self.keys:
                self.unspents.extend(Unspent.get_unspents(chain=self.chain, provider=self.provider, private_keys=[key]))
        return self.unspents

    def get_balance(self, refresh: bool = False) -> int:
        self.get_unspents(refresh)
        return sum([unspent.satoshi for unspent in self.unspents])

    def create_transaction(self, outputs: Optional[List[Tuple]] = None, leftover: Optional[str] = None, fee_rate: Optional[float] = None,
                           unspents: Optional[List[Unspent]] = None, combine: bool = False, pushdatas: Optional[List[Union[str, bytes]]] = None) -> Transaction:
        """create a signed transaction
        :param outputs: list of tuple (address, satoshi). if None then sweep all the unspents to leftover
        :param leftover: transaction change address
        :param fee_rate: 0.5 satoshi per byte if None
        :param unspents: list of unspents, will refresh from service if None
        :param combine: use all available unspents if True
        :param pushdatas: list of OP_RETURN pushdata
        """
        self.unspents = unspents or self.get_unspents(refresh=True)
        if not self.unspents:
            raise InsufficientFundsError('transaction mush have at least one unspent')

        t = Transaction(fee_rate=fee_rate, chain=self.chain, provider=self.provider)
        if pushdatas:
            t.add_output(TxOutput(pushdatas))
        if outputs:
            t.add_outputs([TxOutput(output[0], output[1]) for output in outputs])
        # pick unspent
        if combine or not outputs:
            t.add_inputs([TxInput(unspent) for unspent in self.unspents])
        else:
            picked_unspents = [self.unspents.pop(0)]
            t.add_input(TxInput(picked_unspents[0]))
            while t.fee() < t.estimated_fee() and self.unspents:
                unspent = self.unspents.pop(0)
                picked_unspents.append(unspent)
                t.add_input(TxInput(unspent))
        if t.fee() < t.estimated_fee():
            raise InsufficientFundsError(f'require {t.estimated_fee() + t.satoshi_total_out():} satoshi but only {t.satoshi_total_in()}')
        return t.add_change(leftover).sign()

    def send_transaction(self, outputs: Optional[List[Tuple]] = None, leftover: Optional[str] = None, fee_rate: Optional[float] = None,
                         unspents: Optional[List[Unspent]] = None, combine: bool = False, pushdatas: Optional[List[Union[str, bytes]]] = None) -> Optional[str]:
        """send a transaction
        :param outputs: list of tuple (address, satoshi). if None then sweep all the unspents to leftover
        :param leftover: transaction change address
        :param fee_rate: 0.5 satoshi per byte if None
        :param unspents: list of unspents, will refresh from service if None
        :param combine: use all available unspents if True
        :param pushdatas: list of OP_RETURN pushdata
        :returns: txid if successfully otherwise None
        """
        return self.create_transaction(outputs, leftover, fee_rate, unspents, combine, pushdatas).broadcast()
