from typing import Tuple, Union

from .base58 import base58check_decode
from .constants import Chain, ADDRESS_PREFIX_CHAIN, WIF_PREFIX_CHAIN
from .hash import hash256


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
    returns (public_key_hash_bytes, chain)
    """
    decoded = base58check_decode(address)
    prefix = decoded[:1]
    chain = ADDRESS_PREFIX_CHAIN.get(prefix)
    if not chain:
        raise ValueError(f'unknown P2PKH address prefix {prefix.hex()}')
    return decoded[1:], chain


def address_to_public_key_hash(address: str) -> bytes:
    return decode_p2pkh_address(address)[0]


def decode_wif(wif: str) -> Tuple[bytes, bool, Chain]:
    """
    returns (private_key_bytes, compressed, chain)
    """
    decoded = base58check_decode(wif)
    prefix = decoded[:1]
    chain = WIF_PREFIX_CHAIN.get(prefix)
    if not chain:
        raise ValueError(f'unknown WIF prefix {prefix.hex()}')
    if len(wif) == 52 and decoded[-1] == 1:
        return decoded[1:-1], True, chain
    return decoded[1:], False, chain


def txid(raw: Union[str, bytes]) -> str:
    if isinstance(raw, str):
        raw_bytes = bytes.fromhex(raw)
    elif isinstance(raw, bytes):
        raw_bytes = raw
    else:
        raise TypeError('unsupported type of raw transaction')
    return hash256(raw_bytes)[::-1].hex()
