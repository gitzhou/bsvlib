import pytest

from bsvlib.base58 import base58check_encode, b58_encode
from bsvlib.constants import Chain
from bsvlib.curve import curve
from bsvlib.utils import decode_address, decode_wif, get_pushdata_code, validate_address, resolve_address
from bsvlib.utils import unsigned_to_varint, deserialize_signature, serialize_signature


def test_unsigned_to_varint():
    with pytest.raises(OverflowError):
        unsigned_to_varint(-1)

    assert unsigned_to_varint(0) == bytes.fromhex('00')
    assert unsigned_to_varint(0xfc) == bytes.fromhex('fc')

    assert unsigned_to_varint(0xfd) == bytes.fromhex('fdfd00')
    assert unsigned_to_varint(0xabcd) == bytes.fromhex('fdcdab')

    assert unsigned_to_varint(0x010000) == bytes.fromhex('fe00000100')
    assert unsigned_to_varint(0x12345678) == bytes.fromhex('fe78563412')

    assert unsigned_to_varint(0x0100000000) == bytes.fromhex('ff0000000001000000')
    assert unsigned_to_varint(0x1234567890abcdef) == bytes.fromhex('ffefcdab9078563412')

    with pytest.raises(OverflowError):
        unsigned_to_varint(0x010000000000000000)


def test_address():
    assert decode_address('1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa') == (bytes.fromhex('62e907b15cbf27d5425399ebf6f0fb50ebb88f18'), Chain.MAIN)
    assert decode_address('moEoqh2ZfYU8jN5EG6ERw6E3DmwnkuTdBC') == (bytes.fromhex('54b34b1ba228ba1d75dca5a40a114dc0f13a2687'), Chain.TEST)
    assert decode_address('n34P4t4K6bJtc6qfGU2pqcRix8mUACdNyJ') == (bytes.fromhex('ec4c3733cff428e9a3c1434274b109fbe2a33b62'), Chain.TEST)

    address_invalid_prefix = base58check_encode(b'\xff' + bytes.fromhex('62e907b15cbf27d5425399ebf6f0fb50ebb88f18'))
    with pytest.raises(ValueError, match=r'invalid P2PKH address'):
        decode_address(address_invalid_prefix)

    address_invalid_checksum = b58_encode(b'\x00' + bytes.fromhex('62e907b15cbf27d5425399ebf6f0fb50ebb88f18') + b'\x00\x00\x00\x00')
    with pytest.raises(ValueError, match=r'unmatched base58 checksum'):
        decode_address(address_invalid_checksum)

    assert validate_address('1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa')
    assert validate_address('moEoqh2ZfYU8jN5EG6ERw6E3DmwnkuTdBC')
    assert not validate_address('moEoqh2ZfYU8jN5EG6ERw6E3DmwnkuTdB')
    assert not validate_address('')
    assert not validate_address(address_invalid_prefix)
    assert not validate_address(address_invalid_checksum)


def test_resolve_address():
    assert resolve_address('1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa') == '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa'
    assert resolve_address('') is None
    assert resolve_address('1aaron67')
    assert resolve_address('$aaron67')
    assert resolve_address('@1239')
    assert resolve_address('aaron67@moneybutton.com')


def test_decode_wif():
    private_key_bytes = bytes.fromhex('f97c89aaacf0cd2e47ddbacc97dae1f88bec49106ac37716c451dcdd008a4b62')
    wif_compressed_main = 'L5agPjZKceSTkhqZF2dmFptT5LFrbr6ZGPvP7u4A6dvhTrr71WZ9'
    wif_uncompressed_main = '5KiANv9EHEU4o9oLzZ6A7z4xJJ3uvfK2RLEubBtTz1fSwAbpJ2U'
    wif_compressed_test = 'cVwfreZB3i8iv9JpdSStd9PWhZZGGJCFLS4rEKWfbkahibwhticA'
    wif_uncompressed_test = '93UnxexmsTYCmDJdctz4zacuwxQd5prDmH6rfpEyKkQViAVA3me'

    assert decode_wif(wif_compressed_main) == (private_key_bytes, True, Chain.MAIN)
    assert decode_wif(wif_uncompressed_main) == (private_key_bytes, False, Chain.MAIN)
    assert decode_wif(wif_compressed_test) == (private_key_bytes, True, Chain.TEST)
    assert decode_wif(wif_uncompressed_test) == (private_key_bytes, False, Chain.TEST)

    with pytest.raises(ValueError, match=r'unknown WIF prefix'):
        decode_wif(base58check_encode(b'\xff' + private_key_bytes))


def test_get_pushdata_code():
    assert get_pushdata_code(0x4b) == b'\x4b'
    assert get_pushdata_code(0x4c) == bytes.fromhex('4c4c')
    assert get_pushdata_code(0xff) == bytes.fromhex('4cff')
    assert get_pushdata_code(0x0100) == bytes.fromhex('4d0001')
    assert get_pushdata_code(0xffff) == bytes.fromhex('4dffff')
    assert get_pushdata_code(0x010000) == bytes.fromhex('4e00000100')
    assert get_pushdata_code(0x01020304) == bytes.fromhex('4e04030201')


def test_signature_serialization():
    der1: str = '3045022100fd5647a062d42cdde975ad4796cefd6b5613e731c08e0fb6907f757a60f44b020220350fee392713423ebfcd8026ea29cc95917d823392f07cd6c80f46712650388e'
    r1 = 114587593887127314608220924841831336233967095853165151956820984900193959037698
    s1 = 24000727837347392504013031837120627225728348681623127776947626422811445180558

    der2: str = '304402207e2c6eb8c4b20e251a71c580373a2836e209c50726e5f8b0f4f59f8af00eee1a022019ae1690e2eb4455add6ca5b86695d65d3261d914bc1d7abb40b188c7f46c9a5'
    r2 = 57069924365784604413146650701306419944030991562754207986153667089859857018394
    s2 = 11615408348402409164215774430388304177694127390766203039231142052414850779557

    der3 = '3044022023f093813911a658ac7cbaeb8ba7828b4067ea3582c78f8bd2c38b1f317489ba022000e1e43145a89f0d9d8524798b8ae2ca60ebf3947e35106d5e1ddf398985a033'
    r3 = 16256011036517295435281672405882454685603286080662722236323812471789728336314
    s3 = 399115516115506318232804590771004057701078428754012727453057145885291814963

    assert serialize_signature(r1, s1).hex() == der1
    assert serialize_signature(r1, curve.n - s1).hex() == der1
    assert serialize_signature(r2, s2).hex() == der2
    assert serialize_signature(r2, curve.n - s2).hex() == der2
    assert serialize_signature(r3, s3).hex() == der3
    assert serialize_signature(r3, curve.n - s3).hex() == der3

    assert deserialize_signature(bytes.fromhex(der1)) == (r1, s1)
    assert deserialize_signature(bytes.fromhex(der2)) == (r2, s2)
    with pytest.raises(ValueError, match=r'invalid DER encoded'):
        deserialize_signature(b'')
