from typing import Union, List

from .script import ScriptType, Script, assemble_pushdata
from ..constants import Opcode


class OpReturnScriptType(ScriptType):

    def __repr__(self) -> str:
        return f'<ScriptType:OP_RETURN>'

    @staticmethod
    def locking(**kwargs) -> Script:
        """
        from pushdatas in format List[Union[str, bytes]]
        """
        pushdatas: List[Union[str, bytes]] = kwargs.get('pushdatas')
        script: bytes = Opcode.FALSE + Opcode.RETURN
        for pushdata in pushdatas:
            if isinstance(pushdata, str):
                pushdata_bytes: bytes = pushdata.encode('utf-8')
            elif isinstance(pushdata, bytes):
                pushdata_bytes: bytes = pushdata
            else:
                raise TypeError("can't parse OP_RETURN locking script")
            script += assemble_pushdata(pushdata_bytes)
        return Script(script)

    @staticmethod
    def unlocking(**kwargs) -> Script:
        raise ValueError("OP_RETURN cannot be unlocked")

    @staticmethod
    def estimated_unlocking_byte_length(**kwargs) -> int:
        raise ValueError("OP_RETURN cannot be unlocked")
