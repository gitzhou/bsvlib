import re
from base64 import b64encode, b64decode
from contextlib import suppress
from typing import Tuple, Optional, Union

import requests
from typing_extensions import Literal

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


def unsigned_to_bytes(num: int, byteorder: Literal['big', 'little'] = 'big') -> bytes:
    """
    convert an unsigned int to the least number of bytes as possible.
    """
    return num.to_bytes((num.bit_length() + 7) // 8 or 1, byteorder)


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


def validate_address(address: str, chain: Optional[Chain] = None) -> bool:
    """
    :returns: True if address is a valid bitcoin legacy address (P2PKH)
    """
    with suppress(Exception):
        _, _chain = decode_address(address)
        if chain is not None:
            return _chain == chain
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
    elif byte_length <= 0xffffffff:
        # OP_PUSHDATA4
        return OP.OP_PUSHDATA4 + byte_length.to_bytes(4, 'little')
    else:
        raise ValueError("data too long to encode in a PUSHDATA opcode")


def encode_pushdata(pushdata: bytes, minimal_push: bool = True) -> bytes:
    """encode pushdata with proper opcode
    https://github.com/bitcoin-sv/bitcoin-sv/blob/v1.0.10/src/script/interpreter.cpp#L310-L337
    :param pushdata: bytes you want to push onto the stack in bitcoin script
    :param minimal_push: if True then push data following the minimal push rule
    """
    if minimal_push:
        if pushdata == b'':
            return OP.OP_0
        if len(pushdata) == 1 and 1 <= pushdata[0] <= 16:
            return bytes([OP.OP_1[0] + pushdata[0] - 1])
        if len(pushdata) == 1 and pushdata[0] == 0x81:
            return OP.OP_1NEGATE
    else:
        # non-minimal push requires pushdata != b''
        assert pushdata, 'empty pushdata'
    return get_pushdata_code(len(pushdata)) + pushdata


def encode_int(num: int) -> bytes:
    """
    encode a signed integer you want to push onto the stack in bitcoin script, following the minimal push rule
    """
    if num == 0:
        return OP.OP_0
    negative: bool = num < 0
    octets: bytearray = bytearray(unsigned_to_bytes(-num if negative else num, 'little'))
    if octets[-1] & 0x80:
        octets += b'\x00'
    if negative:
        octets[-1] |= 0x80
    return encode_pushdata(octets)


def deserialize_ecdsa_der(signature: bytes) -> Tuple[int, int]:
    """
    deserialize ECDSA signature from bitcoin strict DER to (r, s)
    """
    try:
        assert signature[0] == 0x30
        assert int(signature[1]) == len(signature) - 2
        # r
        assert signature[2] == 0x02
        r_len = int(signature[3])
        r = int.from_bytes(signature[4: 4 + r_len], 'big')
        # s
        assert signature[4 + r_len] == 0x02
        s_len = int(signature[5 + r_len])
        s = int.from_bytes(signature[-s_len:], 'big')
        return r, s
    except Exception:
        raise ValueError(f'invalid DER encoded {signature.hex()}')


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


def deserialize_ecdsa_recoverable(signature: bytes) -> Tuple[int, int, int]:
    """
    deserialize recoverable ECDSA signature from bytes to (r, s, recovery_id)
    """
    assert len(signature) == 65, 'invalid length of recoverable ECDSA signature'
    recovery_id = signature[-1]
    assert 0 <= recovery_id <= 3, f'invalid recovery id {recovery_id}'
    return int.from_bytes(signature[:32], 'big'), int.from_bytes(signature[32:-1], 'big'), recovery_id


def serialize_ecdsa_recoverable(signature: Tuple[int, int, int]) -> bytes:
    """
    serialize recoverable ECDSA signature from (r, s, recovery_id) to bytes
    """
    r, s, recovery_id = signature
    assert 0 <= recovery_id < 4, f'invalid recovery id {recovery_id}'
    return r.to_bytes(NUMBER_BYTE_LENGTH, 'big') + s.to_bytes(NUMBER_BYTE_LENGTH, 'big') + recovery_id.to_bytes(1, 'big')


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


def stringify_ecdsa_recoverable(signature: bytes, compressed: bool = True) -> str:
    """stringify serialize recoverable ECDSA signature
    :param signature: serialized recoverable ECDSA signature in format "r (32 bytes) + s (32 bytes) + recovery_id (1 byte)"
    :param compressed: True if used compressed public key
    :returns: stringified recoverable signature formatted in base64
    """
    r, s, recovery_id = deserialize_ecdsa_recoverable(signature)
    prefix: int = 27 + recovery_id + (4 if compressed else 0)
    signature: bytes = prefix.to_bytes(1, 'big') + signature[:-1]
    return b64encode(signature).decode('ascii')


def unstringify_ecdsa_recoverable(signature: str) -> Tuple[bytes, bool]:
    """
    :returns: (serialized_recoverable_signature, used_compressed_public_key)
    """
    serialized = b64decode(signature)
    assert len(serialized) == 65, 'invalid length of recoverable ECDSA signature'
    prefix = serialized[0]
    assert 27 <= prefix < 35, f'invalid recoverable ECDSA signature prefix {prefix}'
    compressed = False
    if prefix >= 31:
        compressed = True
        prefix -= 4
    recovery_id = prefix - 27
    return serialized[1:] + recovery_id.to_bytes(1, 'big'), compressed


def bytes_to_bits(octets: Union[str, bytes]) -> str:
    """
    convert bytes to binary 0/1 string
    """
    b: bytes = octets if isinstance(octets, bytes) else bytes.fromhex(octets)
    bits: str = bin(int.from_bytes(b, 'big'))[2:]
    if len(bits) < len(b) * 8:
        bits = '0' * (len(b) * 8 - len(bits)) + bits
    return bits


def bits_to_bytes(bits: str) -> bytes:
    """
    convert binary 0/1 string to the least number of bytes
    """
    return unsigned_to_bytes(int(bits, 2))
