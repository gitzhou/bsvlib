from typing import Union, List

from ..constants import Opcode, PUBLIC_KEY_VALID_BYTE_LENGTH, PUBLIC_KEY_HASH_BYTE_LENGTH, SigHash
from ..utils import unsigned_to_varint, address_to_public_key_hash


def get_pushdata_code(byte_length: int) -> bytes:
    """
    :returns: the corresponding PUSHDATA opcode according to the byte length of pushdata
    """
    if byte_length <= 0x4b:
        return byte_length.to_bytes(1, 'little')
    elif byte_length <= 0xff:
        # OP_PUSHDATA1
        return Opcode.PUSHDATA1 + byte_length.to_bytes(1, 'little')
    elif byte_length <= 0xffff:
        # OP_PUSHDATA2
        return Opcode.PUSHDATA2 + byte_length.to_bytes(2, 'little')
    else:
        # OP_PUSHDATA4
        return Opcode.PUSHDATA4 + byte_length.to_bytes(4, 'little')


def assemble_pushdata(pushdata: bytes) -> bytes:
    """
    :returns: OP_PUSHDATA + pushdata
    """
    return get_pushdata_code(len(pushdata)) + pushdata


class Script:

    def __init__(self, script: Union[str, bytes]):
        """
        create script from hex string or bytes
        """
        if isinstance(script, str):
            # script in hex string
            self.script: bytes = bytes.fromhex(script)
        elif isinstance(script, bytes):
            # script in bytes
            self.script: bytes = script
        else:
            raise TypeError('unsupported script type')

    def serialize(self) -> bytes:
        return self.script

    def hex(self) -> str:
        return self.script.hex()

    def byte_length(self) -> int:
        return len(self.script)

    size = byte_length

    def byte_length_varint(self) -> bytes:
        return unsigned_to_varint(self.byte_length())

    size_varint = byte_length_varint

    def __eq__(self, o: object) -> bool:
        if isinstance(o, Script):
            return self.script == o.script
        return super().__eq__(o)

    def __repr__(self) -> str:
        return self.script.hex()

    @staticmethod
    def p2pkh_locking(value: Union[str, bytes]) -> 'Script':
        """
        :returns: P2PKH locking script from address (str) or public key hash160 (bytes)
        """
        if isinstance(value, str):
            pkh: bytes = address_to_public_key_hash(value)
        elif isinstance(value, bytes):
            pkh: bytes = value
        else:
            raise TypeError('unsupported type when parsing P2PKH locking script')
        assert len(pkh) == PUBLIC_KEY_HASH_BYTE_LENGTH, f'invalid byte length of public key hash'
        return Script(Opcode.DUP + Opcode.HASH160 + assemble_pushdata(pkh) + Opcode.EQUALVERIFY + Opcode.CHECKSIG)

    @staticmethod
    def p2pkh_unlocking(signature: bytes, public_key: bytes, sighash: SigHash) -> 'Script':
        """
        :returns: P2PKH unlocking script
        """
        assert len(public_key) in PUBLIC_KEY_VALID_BYTE_LENGTH, f'invalid byte length of public key'
        return Script(assemble_pushdata(signature + sighash.to_bytes(1, 'little')) + assemble_pushdata(public_key))

    @staticmethod
    def op_return(pushdatas: List[Union[str, bytes]]) -> 'Script':
        """
        :returns: OP_RETURN locking script from pushdatas
        """
        script: bytes = Opcode.FALSE + Opcode.RETURN
        for pushdata in pushdatas:
            if isinstance(pushdata, str):
                pushdata_bytes: bytes = pushdata.encode('utf-8')
            elif isinstance(pushdata, bytes):
                pushdata_bytes: bytes = pushdata
            else:
                raise TypeError('unsupported type when parsing OP_RETURN locking script')
            script += assemble_pushdata(pushdata_bytes)
        return Script(script)
