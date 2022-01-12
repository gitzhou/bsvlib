from typing import Tuple

from .base58 import base58check_decode
from .constants import Chain, ADDRESS_PREFIX_CHAIN_DICT, WIF_PREFIX_CHAIN_DICT, OP, NUMBER_BYTE_LENGTH
from .curve import curve


def unsigned_to_varint(num: int) -> bytes:
    """
    convert an unsigned int to varint.
    """
    if num < 0 or num > 0xffffffffffffffff:
        raise OverflowError(f"can't convert {num} to varint")
    if num <= 0xfc:
        return num.to_bytes(1, 'little')
    elif num <= 0xffff:
        return b'\xfd' + num.to_bytes(2, 'little')
    elif num <= 0xffffffff:
        return b'\xfe' + num.to_bytes(4, 'little')
    else:
        return b'\xff' + num.to_bytes(8, 'little')


def decode_p2pkh_address(address: str) -> Tuple[bytes, Chain]:
    """
    :returns: tuple (public_key_hash_bytes, chain)
    """
    decoded = base58check_decode(address)
    prefix = decoded[:1]
    chain = ADDRESS_PREFIX_CHAIN_DICT.get(prefix)
    if not chain:
        raise ValueError(f'unknown P2PKH address prefix {prefix.hex()}')
    return decoded[1:], chain


def address_to_public_key_hash(address: str) -> bytes:
    return decode_p2pkh_address(address)[0]


def decode_wif(wif: str) -> Tuple[bytes, bool, Chain]:
    """
    :returns: tuple (private_key_bytes, compressed, chain)
    """
    decoded = base58check_decode(wif)
    prefix = decoded[:1]
    chain = WIF_PREFIX_CHAIN_DICT.get(prefix)
    if not chain:
        raise ValueError(f'unknown WIF prefix {prefix.hex()}')
    if len(wif) == 52 and decoded[-1] == 1:
        return decoded[1:-1], True, chain
    return decoded[1:], False, chain


def get_pushdata_code(byte_length: int) -> bytes:
    """
    :returns: the corresponding PUSHDATA opcode according to the byte length of pushdata
    """
    if byte_length <= 0x4b:
        return byte_length.to_bytes(1, 'little')
    elif byte_length <= 0xff:
        # OP_PUSHDATA1
        return OP.OP_PUSHDATA1 + byte_length.to_bytes(1, 'little')
    elif byte_length <= 0xffff:
        # OP_PUSHDATA2
        return OP.OP_PUSHDATA2 + byte_length.to_bytes(2, 'little')
    else:
        # OP_PUSHDATA4
        return OP.OP_PUSHDATA4 + byte_length.to_bytes(4, 'little')


def assemble_pushdata(pushdata: bytes) -> bytes:
    """
    :returns: OP_PUSHDATA + pushdata
    """
    return get_pushdata_code(len(pushdata)) + pushdata


def deserialize_signature(der: bytes) -> Tuple[int, int]:
    """
    deserialize ECDSA bitcoin DER formatted signature to (r, s)
    """
    try:
        assert der[0] == 0x30
        assert int(der[1]) == len(der) - 2
        # r
        assert der[2] == 0x02
        r_len = int(der[3])
        r = int.from_bytes(der[4: 4 + r_len], 'big')
        # s
        assert der[4 + r_len] == 0x02
        s_len = int(der[5 + r_len])
        s = int.from_bytes(der[-s_len:], 'big')
        return r, s
    except Exception:
        raise ValueError(f'invalid DER encoded {der.hex()}')


def serialize_signature(r: int, s: int) -> bytes:
    """
    serialize ECDSA signature (r, s) to bitcoin strict DER format
    """
    # enforce low s value
    if s > curve.n // 2:
        s = curve.n - s
    # r
    r_bytes = r.to_bytes(NUMBER_BYTE_LENGTH, 'big').lstrip(b'\x00')
    if r_bytes[0] & 0x80:
        r_bytes = b'\x00' + r_bytes
    serialized = bytes([2, len(r_bytes)]) + r_bytes
    # s
    s_bytes = s.to_bytes(NUMBER_BYTE_LENGTH, 'big').lstrip(b'\x00')
    if s_bytes[0] & 0x80:
        s_bytes = b'\x00' + s_bytes
    serialized += bytes([2, len(s_bytes)]) + s_bytes
    return bytes([0x30, len(serialized)]) + serialized
