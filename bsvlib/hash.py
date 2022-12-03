import hashlib

from Cryptodome.Hash import RIPEMD160


def sha256(payload: bytes) -> bytes:
    return hashlib.sha256(payload).digest()


def double_sha256(payload: bytes) -> bytes:
    return sha256(sha256(payload))


def ripemd160_sha256(payload: bytes) -> bytes:
    return RIPEMD160.new(sha256(payload)).digest()


hash256 = double_sha256
hash160 = ripemd160_sha256
