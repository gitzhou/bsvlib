import pytest

from bsvlib.base58 import base58check_encode, base58check_decode, b58_encode, b58_decode

BITCOIN_ADDRESS = '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa'
PUBLIC_KEY_HASH = bytes.fromhex('62e907b15cbf27d5425399ebf6f0fb50ebb88f18')
MAIN_ADDRESS_PREFIX = b'\x00'


def test_base58():
    assert b58_encode(b'\x00') == '1'
    assert b58_encode(b'\x00\x00') == '11'
    assert b58_encode(b'hello world') == 'StV1DL6CwTryKyV'

    assert b58_decode('1') == b'\x00'
    assert b58_decode('111') == b'\x00\x00\x00'
    assert b58_decode('StV1DL6CwTryKyV') == b'hello world'


def test_base58check_encode():
    assert base58check_encode(b'hello world') == '3vQB7B6MrGQZaxCuFg4oh'
    assert base58check_encode(MAIN_ADDRESS_PREFIX + PUBLIC_KEY_HASH) == BITCOIN_ADDRESS


def test_base58check_decode():
    assert base58check_decode('3vQB7B6MrGQZaxCuFg4oh') == b'hello world'
    assert base58check_decode(BITCOIN_ADDRESS) == MAIN_ADDRESS_PREFIX + PUBLIC_KEY_HASH
    with pytest.raises(ValueError, match=r'invalid base58 encoded'):
        base58check_decode('l')
    with pytest.raises(ValueError, match=r'unmatched base58 checksum'):
        base58check_decode('L')
