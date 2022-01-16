import pytest

from bsvlib.base58 import unsigned_to_bytes, base58check_encode, base58check_decode, b58_encode, b58_decode

BITCOIN_ADDRESS = '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa'
PUBLIC_KEY_HASH = bytes.fromhex('62e907b15cbf27d5425399ebf6f0fb50ebb88f18')
MAIN_ADDRESS_PREFIX = b'\x00'


def test_unsigned_to_bytes():
    with pytest.raises(OverflowError):
        unsigned_to_bytes(-1)

    assert unsigned_to_bytes(0) == bytes.fromhex('00')
    assert unsigned_to_bytes(num=255, byteorder='big') == bytes.fromhex('ff')
    assert unsigned_to_bytes(num=256, byteorder='big') == bytes.fromhex('0100')

    assert unsigned_to_bytes(num=256, byteorder='little') == bytes.fromhex('0001')


def test_base58():
    assert b58_encode(b'\x00') == '1'
    assert b58_encode(b'\x00\x00') == '11'

    assert b58_decode('1') == b'\x00\x00'
    assert b58_decode('111') == b'\x00\x00\x00\x00'


def test_base58check_encode():
    assert base58check_encode(MAIN_ADDRESS_PREFIX + PUBLIC_KEY_HASH) == BITCOIN_ADDRESS


def test_base58check_decode():
    assert base58check_decode(BITCOIN_ADDRESS) == MAIN_ADDRESS_PREFIX + PUBLIC_KEY_HASH
    with pytest.raises(ValueError, match=r'invalid base58 encoded'):
        base58check_decode('l')
    with pytest.raises(ValueError, match=r'unmatched base58 checksum'):
        base58check_decode('L')
