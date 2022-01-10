from typing import List, Union, Optional

from ..constants import Chain
from ..keys import PrivateKey
from ..script.p2pkh import P2pkhScriptType
from ..script.script import Script, ScriptType
from ..service.provider import Provider
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
        # check if set private keys
        self.private_keys: List[PrivateKey] = kwargs.get('private_keys') if kwargs.get('private_keys') else []
        # if address is not set then try to parse from private keys, otherwise check address only
        self.address: str = kwargs.get('address') or (self.private_keys[0].address() if self.private_keys else None)
        # address is good when either address or private keys is set
        # if unspent type is not set then check address, otherwise check unspent type only
        self.unspent_type: ScriptType = kwargs.get('unspent_type') or (P2pkhScriptType() if self.address else None)
        # if locking_script is not set then parse from address, otherwise check locking_script only
        self.locking_script: Script = kwargs.get('locking_script') or (P2pkhScriptType.locking(address=self.address) if self.address else None)
        # validate
        assert self.txid and self.vout is not None and self.satoshi is not None and self.locking_script, f'bad unspent'

    def __repr__(self) -> str:
        return f'<Unspent outpoint={self.txid}:{self.vout} satoshi={self.satoshi} script={self.locking_script}>'

    @staticmethod
    def get_unspents(value: Union[str, PrivateKey], chain: Chain = Chain.MAIN, provider: Optional[Provider] = None) -> List['Unspent']:
        if isinstance(value, str):
            private_key: Optional[PrivateKey] = None
            address: str = value
        else:
            private_key: Optional[PrivateKey] = value
            address: str = private_key.address()
        unspents_map = Service(chain, provider).get_unspents(address)
        if private_key:
            for unspent_map in unspents_map:
                unspent_map['private_keys'] = [private_key]
        return [Unspent(**unspent_map) for unspent_map in unspents_map]
