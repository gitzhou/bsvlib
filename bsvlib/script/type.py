from abc import abstractmethod, ABCMeta
from typing import Union, List

from .script import Script
from ..constants import PUBLIC_KEY_HASH_BYTE_LENGTH, OP, SIGHASH
from ..utils import address_to_public_key_hash, assemble_pushdata


class ScriptType(metaclass=ABCMeta):
    __instances = {}

    def __new__(cls, *args, **kwargs):
        if cls not in cls.__instances:
            cls.__instances[cls] = super(ScriptType, cls).__new__(cls)
        return cls.__instances[cls]

    @classmethod
    @abstractmethod
    def unlocking(cls, **kwargs) -> Script:
        """
        :returns: unlocking script
        """
        raise NotImplementedError('ScriptType.unlocking')

    @classmethod
    @abstractmethod
    def estimated_unlocking_byte_length(cls, **kwargs) -> int:
        """
        :returns: estimated byte length of signed unlocking script
        """
        raise NotImplementedError('ScriptType.estimated_unlocking_byte_length')


class UnknownScriptType(ScriptType):

    def __repr__(self) -> str:
        return f'<ScriptType:Unknown>'

    @classmethod
    def unlocking(cls, **kwargs) -> Script:
        raise ValueError("don't know how to unlock for script of unknown type")

    @classmethod
    def estimated_unlocking_byte_length(cls, **kwargs) -> int:
        raise ValueError("don't know how to unlock for script of unknown type")


class P2pkhScriptType(ScriptType):

    def __repr__(self) -> str:
        return f'<ScriptType:P2PKH>'

    @classmethod
    def locking(cls, value: Union[str, bytes]) -> Script:
        """
        from address (str) or public key hash160 (bytes)
        """
        if isinstance(value, str):
            pkh: bytes = address_to_public_key_hash(value)
        elif isinstance(value, bytes):
            pkh: bytes = value
        else:
            raise TypeError("can't parse P2PKH locking script")
        assert len(pkh) == PUBLIC_KEY_HASH_BYTE_LENGTH, f'invalid byte length of public key hash'
        return Script(OP.DUP + OP.HASH160 + assemble_pushdata(pkh) + OP.EQUALVERIFY + OP.CHECKSIG)

    @classmethod
    def unlocking(cls, **kwargs) -> Script:
        signature: bytes = kwargs.get('signatures')[0]
        public_key: bytes = kwargs.get('private_keys')[0].public_key().serialize()
        sighash: SIGHASH = kwargs.get('sighash')
        return Script(assemble_pushdata(signature + sighash.to_bytes(1, 'little')) + assemble_pushdata(public_key))

    @classmethod
    def estimated_unlocking_byte_length(cls, **kwargs) -> int:
        return 148 if kwargs.get('private_keys')[0].compressed else 180


class OpReturnScriptType(ScriptType):

    def __repr__(self) -> str:
        return f'<ScriptType:OP_RETURN>'

    @classmethod
    def locking(cls, pushdatas: List[Union[str, bytes]]) -> Script:
        script: bytes = OP.FALSE + OP.RETURN
        for pushdata in pushdatas:
            if isinstance(pushdata, str):
                pushdata_bytes: bytes = pushdata.encode('utf-8')
            elif isinstance(pushdata, bytes):
                pushdata_bytes: bytes = pushdata
            else:
                raise TypeError("can't parse OP_RETURN locking script")
            script += assemble_pushdata(pushdata_bytes)
        return Script(script)

    @classmethod
    def unlocking(cls, **kwargs) -> Script:
        raise ValueError("OP_RETURN cannot be unlocked")

    @classmethod
    def estimated_unlocking_byte_length(cls, **kwargs) -> int:
        raise ValueError("OP_RETURN cannot be unlocked")
