import hashlib


def sha256(payload: bytes) -> bytes:
    return hashlib.sha256(payload).digest()


def double_sha256(payload: bytes) -> bytes:
    return sha256(sha256(payload))


def ripemd160_sha256(payload: bytes) -> bytes:
    return hashlib.new('ripemd160', sha256(payload)).digest()


hash256 = double_sha256
hash160 = ripemd160_sha256
