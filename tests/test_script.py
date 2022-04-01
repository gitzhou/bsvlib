import pytest

from bsvlib.constants import SIGHASH, OP
from bsvlib.keys import Key
from bsvlib.script.script import Script
from bsvlib.script.type import P2pkhScriptType, OpReturnScriptType, P2pkScriptType, BareMultisigScriptType
from bsvlib.utils import address_to_public_key_hash, encode_int, encode_pushdata


def test_script():
    locking_script = '76a9146a176cd51593e00542b8e1958b7da2be97452d0588ac'
    assert Script(locking_script) == Script(bytes.fromhex(locking_script))
    assert Script(locking_script).hex() == locking_script

    assert Script().serialize() == b''
    assert Script().hex() == ''
    assert Script().byte_length() == 0

    with pytest.raises(TypeError, match=r'unsupported script type'):
        # noinspection PyTypeChecker
        Script(1)


def test_p2pkh():
    address = '1AfxgwYJrBgriZDLryfyKuSdBsi59jeBX9'
    locking_script = '76a9146a176cd51593e00542b8e1958b7da2be97452d0588ac'
    assert P2pkhScriptType.locking(address) == Script(locking_script)
    assert P2pkhScriptType.locking(address_to_public_key_hash(address)) == Script(locking_script)

    with pytest.raises(TypeError, match=r"can't parse P2PKH locking script"):
        # noinspection PyTypeChecker
        P2pkhScriptType.locking(1)

    key_compressed = Key('L5agPjZKceSTkhqZF2dmFptT5LFrbr6ZGPvP7u4A6dvhTrr71WZ9')
    key_uncompressed = Key('5KiANv9EHEU4o9oLzZ6A7z4xJJ3uvfK2RLEubBtTz1fSwAbpJ2U')
    assert P2pkhScriptType.estimated_unlocking_byte_length(private_keys=[key_compressed]) == 107
    assert P2pkhScriptType.estimated_unlocking_byte_length(private_keys=[key_uncompressed]) == 139

    payload = {'signatures': [b'\x00'], 'private_keys': [key_compressed], 'sighash': SIGHASH.ALL_FORKID}
    assert P2pkhScriptType.unlocking(**payload).hex() == '020041' + '21' + key_compressed.public_key().hex()


def test_op_return():
    assert OpReturnScriptType.locking(['0']) == Script('006a0130')
    assert OpReturnScriptType.locking(['0' * 0x4b]) == Script('006a' + '4b' + '30' * 0x4b)
    assert OpReturnScriptType.locking(['0' * 0x4c]) == Script('006a' + '4c4c' + '30' * 0x4c)
    assert OpReturnScriptType.locking(['0' * 0x0100]) == Script('006a' + '4d0001' + '30' * 0x0100)
    assert OpReturnScriptType.locking([b'\x31\x32', '345']) == Script('006a' + '023132' + '03333435')

    with pytest.raises(TypeError, match=r"can't parse OP_RETURN locking script"):
        # noinspection PyTypeChecker
        OpReturnScriptType.locking([1])


def test_p2pk():
    public_key = Key('L5agPjZKceSTkhqZF2dmFptT5LFrbr6ZGPvP7u4A6dvhTrr71WZ9').public_key()
    assert P2pkScriptType.locking(public_key.hex()) == P2pkScriptType.locking(public_key.serialize())

    with pytest.raises(TypeError, match=r"can't parse P2PK locking script"):
        # noinspection PyTypeChecker
        P2pkScriptType.locking(1)

    payload = {'signatures': [b'\x00'], 'sighash': SIGHASH.ALL_FORKID}
    assert P2pkScriptType.unlocking(**payload).hex() == '020041'


def test_bare_multisig():
    pk1, pk2, pk3 = Key().public_key(), Key().public_key(), Key().public_key()
    pks = [pk1.hex(), pk2.serialize(compressed=False), pk3.serialize()]
    encoded_pks = b''.join([encode_pushdata(pk if isinstance(pk, bytes) else bytes.fromhex(pk)) for pk in pks])
    expected_locking = encode_int(2) + encoded_pks + encode_int(3) + OP.OP_CHECKMULTISIG
    assert BareMultisigScriptType.locking(pks, 2).serialize() == expected_locking

    payload = {'signatures': [b'\x00', b'\x01'], 'sighash': SIGHASH.ALL_FORKID}
    assert BareMultisigScriptType.unlocking(**payload).hex() == '00' + '020041' + '020141'
