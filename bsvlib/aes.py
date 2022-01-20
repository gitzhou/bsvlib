from Cryptodome.Cipher import AES


class InvalidPadding(Exception):
    pass


def append_pkcs7_padding(message: bytes) -> bytes:
    pad = 16 - (len(message) % 16)
    return message + bytes([pad]) * pad


def strip_pkcs7_padding(message: bytes) -> bytes:
    if len(message) % 16 != 0 or len(message) == 0:
        raise InvalidPadding("invalid length")
    pad = message[-1]
    if not 1 <= pad <= 16:
        raise InvalidPadding("invalid padding byte (out of range)")
    for i in message[-pad:]:
        if i != pad:
            raise InvalidPadding("invalid padding byte (inconsistent)")
    return message[0:-pad]


def aes_encrypt_with_iv(key: bytes, iv: bytes, message: bytes) -> bytes:
    return AES.new(key, AES.MODE_CBC, iv).encrypt(append_pkcs7_padding(message))


def aes_decrypt_with_iv(key: bytes, iv: bytes, message: bytes) -> bytes:
    return strip_pkcs7_padding(AES.new(key, AES.MODE_CBC, iv).decrypt(message))
