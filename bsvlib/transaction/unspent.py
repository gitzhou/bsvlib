from typing import List, Union, Optional

from .script import Script
from ..constants import TxOutType, Chain
from ..keys import PrivateKey
from ..service.service import Service


class Unspent:
    def __init__(self, **kwargs):
        """
        if unspent type is P2PKH, then set either private key or oddress is enought
        otherwise, then essential to set both locking script and unspent type
        """
        self.txid: str = kwargs.get('txid')
        self.vout: int = int(kwargs.get('vout'))
        self.satoshi: int = int(kwargs.get('satoshi'))
        self.height: int = -1 if kwargs.get('height') is None else kwargs.get('height')
        self.confirmation: int = 0 if kwargs.get('confirmation') is None else kwargs.get('confirmation')
        # check if set private_key
        self.private_key: PrivateKey = kwargs.get('private_key') if kwargs.get('private_key') else []
        # if address is not set then try to parse from private_key, otherwise check address only
        self.address: str = kwargs.get('address') or (self.private_key.address() if self.private_key else None)
        # address is good when either address or private key is set
        # if unspent type is not set then check address, otherwise check unspent type only
        self.unspent_type: TxOutType = kwargs.get('unspent_type') or (TxOutType.P2PKH if self.address else TxOutType.UNKNOWN)
        # if locking_script is not set then parse from address, otherwise check locking_script only
        self.locking_script: Script = kwargs.get('locking_script') or (Script.p2pkh_locking(self.address) if self.address else None)
        # validate
        assert self.txid and self.vout is not None and self.satoshi is not None and self.locking_script, f'bad unspent'

    def __repr__(self) -> str:
        return f'<Unspent outpoint={self.txid}:{self.vout} satoshi={self.satoshi} script={self.locking_script}>'

    @staticmethod
    def get_unspents(value: Union[str, PrivateKey], chain: Chain = Chain.MAIN) -> List['Unspent']:
        if isinstance(value, str):
            private_key: Optional[PrivateKey] = None
            address: str = value
        else:
            private_key: Optional[PrivateKey] = value
            address: str = private_key.address()
        unspents_map = Service(chain).get_unspents(address)
        if private_key:
            for unspent_map in unspents_map:
                unspent_map['private_key'] = private_key
        return [Unspent(**unspent_map) for unspent_map in unspents_map]
