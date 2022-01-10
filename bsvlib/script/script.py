from abc import abstractmethod, ABCMeta
from typing import Union

from ..constants import Opcode
from ..utils import unsigned_to_varint


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


class ScriptType(metaclass=ABCMeta):

    @staticmethod
    @abstractmethod
    def locking(**kwargs) -> Script:
        """
        :returns: locking script
        """
        raise NotImplementedError('ScriptType.locking')

    @staticmethod
    @abstractmethod
    def unlocking(**kwargs) -> Script:
        """
        :returns: unlocking script
        """
        raise NotImplementedError('ScriptType.unlocking')

    @staticmethod
    @abstractmethod
    def estimated_unlocking_byte_length(**kwargs) -> int:
        """
        :returns: estimated byte length of signed unlocking script
        """
        raise NotImplementedError('ScriptType.estimated_unlocking_byte_length')
