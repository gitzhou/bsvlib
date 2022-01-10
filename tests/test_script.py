from bsvlib.script.script import Script
from bsvlib.script.type import P2pkhScriptType, OpReturnScriptType


def test_p2pkh():
    address = '1AfxgwYJrBgriZDLryfyKuSdBsi59jeBX9'
    locking_script = '76a9146a176cd51593e00542b8e1958b7da2be97452d0588ac'
    assert P2pkhScriptType.locking(address) == Script(locking_script)


def test_op_return():
    assert OpReturnScriptType.locking(['0']) == Script('006a0130')
    assert OpReturnScriptType.locking(['0' * 0x4b]) == Script('006a' + '4b' + '30' * 0x4b)
    assert OpReturnScriptType.locking(['0' * 0x4c]) == Script('006a' + '4c4c' + '30' * 0x4c)
    assert OpReturnScriptType.locking(['0' * 0x0100]) == Script('006a' + '4d0001' + '30' * 0x0100)
