from abc import abstractmethod, ABCMeta
from typing import Union, List

from .script import Script
from ..constants import PUBLIC_KEY_HASH_BYTE_LENGTH, OP, SIGHASH, PUBLIC_KEY_BYTE_LENGTH_LIST
from ..utils import address_to_public_key_hash, encode_pushdata, encode_int


class ScriptType(metaclass=ABCMeta):
    """
    script type demonstration in singleton
    """
    __instances = {}

    def __new__(cls, *args, **kwargs):
        if cls not in cls.__instances:
            cls.__instances[cls] = super(ScriptType, cls).__new__(cls)
        return cls.__instances[cls]

    @classmethod
    @abstractmethod
    def unlocking(cls, **kwargs) -> Script:
        """kwargs will pass the following at least
        {
            'signatures': List[bytes] DER formatted,
            'private_keys': List[bsvlib.keys.PrivateKey],
            'sighash': bsvlib.constants.SIGHASH,
        }
        :returns: unlocking script
        """
        raise NotImplementedError('ScriptType.unlocking')

    @classmethod
    @abstractmethod
    def estimated_unlocking_byte_length(cls, **kwargs) -> int:
        """kwargs will pass the following at least
        {
            'private_keys': List[bsvlib.keys.PrivateKey],
        }
        :returns: estimated byte length of signed unlocking script
        """
        raise NotImplementedError('ScriptType.estimated_unlocking_byte_length')


class UnknownScriptType(ScriptType):  # pragma: no cover

    def __str__(self) -> str:
        return '<ScriptType:Unknown>'

    @classmethod
    def unlocking(cls, **kwargs) -> Script:
        raise ValueError("don't know how to unlock for script of unknown type")

    @classmethod
    def estimated_unlocking_byte_length(cls, **kwargs) -> int:
        raise ValueError("don't know how to unlock for script of unknown type")


class P2pkhScriptType(ScriptType):

    def __str__(self) -> str:  # pragma: no cover
        return '<ScriptType:P2PKH>'

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
        assert len(pkh) == PUBLIC_KEY_HASH_BYTE_LENGTH, 'invalid byte length of public key hash'
        return Script(OP.OP_DUP + OP.OP_HASH160 + encode_pushdata(pkh) + OP.OP_EQUALVERIFY + OP.OP_CHECKSIG)

    @classmethod
    def unlocking(cls, **kwargs) -> Script:
        signature: bytes = kwargs.get('signatures')[0]
        public_key: bytes = kwargs.get('public_key') or kwargs.get('private_keys')[0].public_key().serialize()
        sighash: SIGHASH = kwargs.get('sighash')
        return Script(encode_pushdata(signature + sighash.to_bytes(1, 'little')) + encode_pushdata(public_key))

    @classmethod
    def estimated_unlocking_byte_length(cls, **kwargs) -> int:
        return 107 if kwargs.get('private_keys')[0].compressed else 139


class OpReturnScriptType(ScriptType):

    def __str__(self) -> str:  # pragma: no cover
        return '<ScriptType:OP_RETURN>'

    @classmethod
    def locking(cls, pushdatas: List[Union[str, bytes]]) -> Script:
        script: bytes = OP.OP_FALSE + OP.OP_RETURN
        for pushdata in pushdatas:
            if isinstance(pushdata, str):
                pushdata_bytes: bytes = pushdata.encode('utf-8')
            elif isinstance(pushdata, bytes):
                pushdata_bytes: bytes = pushdata
            else:
                raise TypeError("can't parse OP_RETURN locking script")
            script += encode_pushdata(pushdata_bytes, minimal_push=False)
        return Script(script)

    @classmethod
    def unlocking(cls, **kwargs) -> Script:  # pragma: no cover
        raise ValueError("OP_RETURN cannot be unlocked")

    @classmethod
    def estimated_unlocking_byte_length(cls, **kwargs) -> int:  # pragma: no cover
        raise ValueError("OP_RETURN cannot be unlocked")


class P2pkScriptType(ScriptType):

    def __str__(self) -> str:  # pragma: no cover
        return '<ScriptType:P2PK>'

    @classmethod
    def locking(cls, public_key: Union[str, bytes]) -> Script:
        """
        from public key in format str or bytes
        """
        if isinstance(public_key, str):
            pk: bytes = bytes.fromhex(public_key)
        elif isinstance(public_key, bytes):
            pk: bytes = public_key
        else:
            raise TypeError("can't parse P2PK locking script")
        assert len(pk) in PUBLIC_KEY_BYTE_LENGTH_LIST, 'invalid byte length of public key'
        return Script(encode_pushdata(pk) + OP.OP_CHECKSIG)

    @classmethod
    def unlocking(cls, **kwargs) -> Script:
        signature: bytes = kwargs.get('signatures')[0]
        sighash: SIGHASH = kwargs.get('sighash')
        return Script(encode_pushdata(signature + sighash.to_bytes(1, 'little')))

    @classmethod
    def estimated_unlocking_byte_length(cls, **kwargs) -> int:  # pragma: no cover
        return 73


class BareMultisigScriptType(ScriptType):

    def __str__(self) -> str:  # pragma: no cover
        return '<ScriptType:BareMultisig>'

    @classmethod
    def locking(cls, participants: List[Union[str, bytes]], threshold: int) -> Script:
        assert 1 <= threshold <= len(participants), 'bad threshold or number of participants'
        script: bytes = encode_int(threshold)
        for participant in participants:
            assert type(participant).__name__ in ['str', 'bytes'], 'unsupported public key type'
            if isinstance(participant, str):
                participant = bytes.fromhex(participant)
            assert len(participant) in PUBLIC_KEY_BYTE_LENGTH_LIST, 'invalid byte length of public key'
            script += encode_pushdata(participant)
        return Script(script + encode_int(len(participants)) + OP.OP_CHECKMULTISIG)

    @classmethod
    def unlocking(cls, **kwargs) -> Script:
        signatures: List[bytes] = kwargs.get('signatures')
        sighash: SIGHASH = kwargs.get('sighash')
        script: bytes = OP.OP_0
        for signature in signatures:
            script += encode_pushdata(signature + sighash.to_bytes(1, 'little'))
        return Script(script)

    @classmethod
    def estimated_unlocking_byte_length(cls, **kwargs) -> int:  # pragma: no cover
        return 1 + 73 * len(kwargs.get('private_keys'))
