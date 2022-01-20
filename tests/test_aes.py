from secrets import randbits

import pytest

from bsvlib.aes import append_pkcs7_padding, strip_pkcs7_padding, aes_encrypt_with_iv, aes_decrypt_with_iv, InvalidPadding


def test():
    message: bytes = b'hello world'
    padding_message: bytes = b'hello world\x05\x05\x05\x05\x05'
    assert append_pkcs7_padding(message) == padding_message
    assert strip_pkcs7_padding(padding_message) == message

    message: bytes = b'\x00' * 16
    padding_message: bytes = message + b'\x10' * 16
    assert append_pkcs7_padding(message) == padding_message
    assert strip_pkcs7_padding(padding_message) == message

    with pytest.raises(InvalidPadding, match=r'invalid length'):
        strip_pkcs7_padding(b'')
    with pytest.raises(InvalidPadding, match=r'invalid length'):
        strip_pkcs7_padding(b'\x00' * 15)
    with pytest.raises(InvalidPadding, match=r'invalid padding byte \(out of range\)'):
        strip_pkcs7_padding(b'hello world\x05\x05\x05\x05\xff')
    with pytest.raises(InvalidPadding, match=r'invalid padding byte \(inconsistent\)'):
        strip_pkcs7_padding(b'hello world\x05\x05\x05\x04\x05')

    key_byte_length = 16
    key = randbits(key_byte_length * 8).to_bytes(key_byte_length, 'big')
    iv = randbits(key_byte_length * 8).to_bytes(key_byte_length, 'big')
    encrypted: bytes = aes_encrypt_with_iv(key, iv, message)
    assert message == aes_decrypt_with_iv(key, iv, encrypted)
