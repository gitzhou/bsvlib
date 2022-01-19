import re
from base64 import b64encode, b64decode
from contextlib import suppress
from typing import Tuple, Optional

import requests

from .base58 import base58check_decode
from .constants import Chain, ADDRESS_PREFIX_CHAIN_DICT, WIF_PREFIX_CHAIN_DICT, OP, NUMBER_BYTE_LENGTH, HTTP_REQUEST_TIMEOUT
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


def decode_address(address: str) -> Tuple[bytes, Chain]:
    """
    :returns: tuple (public_key_hash_bytes, chain)
    """
    if not re.match(r'^[1mn][a-km-zA-HJ-NP-Z1-9]{24,33}$', address):
        # - a Bitcoin address is between 25 and 34 characters long;
        # - the address always starts with a 1, m, or n
        # - an address can contain all alphanumeric characters, with the exceptions of 0, O, I, and l.
        raise ValueError(f'invalid P2PKH address {address}')
    decoded = base58check_decode(address)
    prefix = decoded[:1]
    chain = ADDRESS_PREFIX_CHAIN_DICT.get(prefix)
    return decoded[1:], chain


def validate_address(address: str) -> bool:
    """
    :returns: True if address is a valid bitcoin legacy address (P2PKH)
    """
    with suppress(Exception):
        decode_address(address)
        return True
    return False


def resolve_address(receiver: str) -> Optional[str]:
    """convert paymail, HandCash handle, RelayX handle to bitcoin legacy address
    :returns: None if failure
    """
    with suppress(Exception):
        if validate_address(receiver):
            # receiver is already a legacy address
            return receiver
        # receiver is an alias
        r = requests.get(f'https://api.polynym.io/getAddress/{receiver}', timeout=HTTP_REQUEST_TIMEOUT)
        r.raise_for_status()
        address = r.json().get('address')
        decode_address(address)
        return address
    return None


def address_to_public_key_hash(address: str) -> bytes:
    """
    :returns: convert P2PKH address to the corresponding public key hash
    """
    return decode_address(address)[0]


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


def deserialize_ecdsa_der(der: bytes) -> Tuple[int, int]:
    """
    deserialize ECDSA signature from bitcoin DER to (r, s)
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


def serialize_ecdsa_der(signature: Tuple[int, int]) -> bytes:
    """
    serialize ECDSA signature (r, s) to bitcoin strict DER format
    """
    r, s = signature
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


def serialize_text(text: str) -> bytes:
    """
    serialize plain text to bytes in format: varint_length + text.utf-8
    """
    message: bytes = text.encode('utf-8')
    return unsigned_to_varint(len(message)) + message


def text_digest(text: str) -> bytes:
    """
    :returns: the digest of arbitrary text when signing with bitcoin private key
    """
    return serialize_text('Bitcoin Signed Message:\n') + serialize_text(text)


def serialize_ecdsa_recoverable(signature: Tuple[int, int, int], compressed: bool = True) -> str:
    """serialize recoverable ECDSA signature (recovery_id, r, s), compressed is True if used compressed public key
    :returns: serialized recoverable signature formatted in base64
    """
    recovery_id, r, s = signature
    prefix: int = 27 + recovery_id + (4 if compressed else 0)
    signature: bytes = prefix.to_bytes(1, 'big') + r.to_bytes(NUMBER_BYTE_LENGTH, 'big') + s.to_bytes(NUMBER_BYTE_LENGTH, 'big')
    return b64encode(signature).decode('ascii')


def deserialize_ecdsa_recoverable(signature: str) -> Tuple[Tuple[int, int, int], bool]:
    """
    :returns: ((recovery_id, r, s), used_compressed_public_key)
    """
    signature_bytes = b64decode(signature)
    assert len(signature_bytes) == 65, f'invalid recoverable ECDSA signature {signature}'
    prefix, r, s = signature_bytes[0], int.from_bytes(signature_bytes[1:33], 'big'), int.from_bytes(signature_bytes[33:], 'big')
    assert 27 <= prefix < 35, f'invalid recoverable ECDSA signature prefix {prefix}'
    compressed = False
    if prefix >= 31:
        compressed = True
        prefix -= 4
    recovery_id = prefix - 27
    return (recovery_id, r, s), compressed
