from .script import ScriptType, Script, assemble_pushdata
from ..constants import PUBLIC_KEY_HASH_BYTE_LENGTH, Opcode, SigHash
from ..utils import address_to_public_key_hash


class P2pkhScriptType(ScriptType):

    def __repr__(self) -> str:
        return f'<ScriptType:P2PKH>'

    @staticmethod
    def locking(**kwargs) -> Script:
        """
        from address (str) or public key hash160 (bytes)
        """
        if kwargs.get('address') and isinstance(kwargs.get('address'), str):
            pkh: bytes = address_to_public_key_hash(kwargs.get('address'))
        elif kwargs.get('public_key_hash') and isinstance(kwargs.get('public_key_hash'), bytes):
            pkh: bytes = kwargs.get('public_key_hash')
        else:
            raise TypeError("can't parse P2PKH locking script")
        assert len(pkh) == PUBLIC_KEY_HASH_BYTE_LENGTH, f'invalid byte length of public key hash'
        return Script(Opcode.DUP + Opcode.HASH160 + assemble_pushdata(pkh) + Opcode.EQUALVERIFY + Opcode.CHECKSIG)

    @staticmethod
    def unlocking(**kwargs) -> Script:
        signature: bytes = kwargs.get('signature')
        public_key: bytes = kwargs.get('public_key')
        sighash: SigHash = kwargs.get('sighash')
        return Script(assemble_pushdata(signature + sighash.to_bytes(1, 'little')) + assemble_pushdata(public_key))

    @staticmethod
    def estimated_unlocking_byte_length(**kwargs) -> int:
        return 148 if kwargs.get('compressed') else 180
