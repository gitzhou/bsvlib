from secrets import randbelow
from typing import Optional, Union, Callable, Tuple

from .base58 import base58check_encode
from .constants import Chain, CHAIN_ADDRESS_PREFIX_DICT, CHAIN_WIF_PREFIX_DICT
from .constants import NUMBER_BYTE_LENGTH
from .constants import PUBLIC_KEY_BYTE_LENGTH_LIST, PUBLIC_KEY_COMPRESSED_PREFIX_LIST, PUBLIC_KEY_UNCOMPRESSED_PREFIX
from .constants import PUBLIC_KEY_COMPRESSED_BYTE_LENGTH, PUBLIC_KEY_UNCOMPRESSED_BYTE_LENGTH, PUBLIC_KEY_COMPRESSED_EVEN_Y_PREFIX_DICT
from .curve import Point
from .curve import curve, get_y, modular_inverse, add, multiply
from .hash import hash160, hash256
from .script.script import Script
from .script.type import P2pkhScriptType
from .utils import decode_wif, text_digest, serialize_ecdsa_recoverable, deserialize_ecdsa_recoverable


class PublicKey:

    def __init__(self, public_key: Union[str, bytes, Point]):
        """
        create public key from serialized hex string or bytes, or curve point
        """
        self.compressed: bool = True  # default compressed format public key

        if isinstance(public_key, Point):
            # from curve point
            self.point: Point = public_key
        else:
            if isinstance(public_key, str):
                # from serialized public key in hex string
                pk: bytes = bytes.fromhex(public_key)
            elif isinstance(public_key, bytes):
                # from serialized public key in bytes
                pk: bytes = public_key
            else:
                raise TypeError('unsupported public key type')
            # here we have serialized public key
            assert len(pk) in PUBLIC_KEY_BYTE_LENGTH_LIST, 'invalid byte length of public key'
            prefix: bytes = pk[:1]
            if prefix in PUBLIC_KEY_COMPRESSED_PREFIX_LIST:
                assert len(pk) == PUBLIC_KEY_COMPRESSED_BYTE_LENGTH, 'invalid byte length of compressed public key'
                x: int = int.from_bytes(pk[1:], 'big')
                self.point: Point = Point(x, get_y(x, pk[0] % 2 == 0))
            elif prefix == PUBLIC_KEY_UNCOMPRESSED_PREFIX:
                assert len(pk) == PUBLIC_KEY_UNCOMPRESSED_BYTE_LENGTH, 'invalid byte length of uncompressed public key'
                self.compressed = False
                self.point: Point = Point(int.from_bytes(pk[1:33], 'big'), int.from_bytes(pk[33:], 'big'))
            else:
                raise ValueError('invalid public key prefix')

        assert self.point, 'bad public key'

    def serialize(self, compressed: Optional[bool] = None) -> bytes:
        compressed = self.compressed if compressed is None else compressed
        x, y = self.point.x, self.point.y
        if compressed:
            return PUBLIC_KEY_COMPRESSED_EVEN_Y_PREFIX_DICT[y % 2 == 0] + int.to_bytes(x, NUMBER_BYTE_LENGTH, 'big')
        return PUBLIC_KEY_UNCOMPRESSED_PREFIX + int.to_bytes(x, NUMBER_BYTE_LENGTH, 'big') + int.to_bytes(y, NUMBER_BYTE_LENGTH, 'big')

    def hex(self, compressed: Optional[bool] = None) -> str:
        return self.serialize(compressed).hex()

    def hash160(self, compressed: Optional[bool] = None) -> bytes:
        """
        :returns: public key hash corresponding to this public key
        """
        return hash160(self.serialize(compressed))

    hash = hash160

    def locking_script(self, compressed: Optional[bool] = None) -> Script:
        """
        :returns: P2PKH locking script corresponding to this public key
        """
        return P2pkhScriptType.locking(self.hash160(compressed))

    def address(self, compressed: Optional[bool] = None, chain: Chain = Chain.MAIN) -> str:
        """
        :returns: P2PKH address corresponding to this public key
        """
        return base58check_encode(CHAIN_ADDRESS_PREFIX_DICT.get(chain) + self.hash160(compressed))

    def __eq__(self, o: object) -> bool:
        if isinstance(o, PublicKey):
            return self.point == o.point
        return super().__eq__(o)  # pragma: no cover

    def verify(self, signature: Tuple[int, int], message: bytes, hasher: Callable[[bytes], bytes] = hash256) -> bool:
        """
        verify ECDSA signature (r, s)
        """
        e = int.from_bytes(hasher(message), 'big')
        r, s = signature
        w = modular_inverse(s, curve.n)
        u1 = (w * e) % curve.n
        u2 = (w * r) % curve.n
        x, _ = add(multiply(u1, curve.g), multiply(u2, self.point))
        return r == (x % curve.n)

    def verify_recoverable(self, signature: Tuple[int, int, int], message: bytes, hasher: Callable[[bytes], bytes] = hash256) -> bool:
        """
        verify recoverable ECDSA signature (recovery_id, r, s)
        """
        _, r, s = signature
        return self.verify((r, s), message, hasher) and self == recover_public_key(signature, message, hasher)


class PrivateKey:

    def __init__(self, private_key: Union[str, int, bytes, None] = None, chain: Optional[Chain] = None):
        """
        create private key from WIF (str), or int, or bytes
        random a new private key if None
        """
        self.chain: Chain = chain or Chain.MAIN
        self.compressed: bool = True  # default compressed wif
        if private_key is None:
            k = randbelow(curve.n)
            while not k:  # pragma: no cover
                k = randbelow(curve.n)
        else:
            if isinstance(private_key, str):
                # from wif
                private_key_bytes, self.compressed, self.chain = decode_wif(private_key)
                k = int.from_bytes(private_key_bytes, 'big')
            elif isinstance(private_key, int):
                # from private key as int
                k = private_key
            elif isinstance(private_key, bytes):
                # from private key integer in bytes
                k = int.from_bytes(private_key, 'big')
            else:
                raise TypeError('unsupported private key type')
        self.key: int = k
        assert 0 < self.key < curve.n, 'bad private key'

    def public_key(self) -> PublicKey:
        pk = PublicKey(multiply(self.key, curve.g))
        pk.compressed = self.compressed
        return pk

    def locking_script(self, compressed: Optional[bool] = None) -> Script:
        """
        :returns: P2PKH locking script corresponding to this private key
        """
        compressed = self.compressed if compressed is None else compressed
        return self.public_key().locking_script(compressed)

    def address(self, compressed: Optional[bool] = None, chain: Optional[Chain] = None) -> str:
        """
        :returns: P2PKH address corresponding to this private key
        """
        compressed = self.compressed if compressed is None else compressed
        chain = chain or self.chain
        return self.public_key().address(compressed, chain)

    def wif(self, compressed: Optional[bool] = None, chain: Optional[Chain] = None) -> str:
        compressed = self.compressed if compressed is None else compressed
        chain = chain or self.chain
        key_bytes = self.serialize()
        compressed_bytes = b'\x01' if compressed else b''
        return base58check_encode(CHAIN_WIF_PREFIX_DICT.get(chain) + key_bytes + compressed_bytes)

    def int(self) -> int:
        return self.key

    def hex(self) -> str:
        return self.serialize().hex()

    def serialize(self) -> bytes:
        return self.key.to_bytes(NUMBER_BYTE_LENGTH, 'big')

    def __eq__(self, o: object) -> bool:
        if isinstance(o, PrivateKey):
            return self.key == o.key
        return super().__eq__(o)  # pragma: no cover

    def sign(self, message: bytes, hasher: Callable[[bytes], bytes] = hash256) -> Tuple[int, int]:
        """
        :returns: ECDSA signature in format (r, s)
        """
        e = int.from_bytes(hasher(message), 'big')
        r, s = 0, 0
        while not r or not s:
            k = PrivateKey()
            r = k.public_key().point.x % curve.n
            s = ((e + r * self.key) * modular_inverse(k.key, curve.n)) % curve.n
        return r, s

    def verify(self, signature: Tuple[int, int], message: bytes, hasher: Callable[[bytes], bytes] = hash256) -> bool:
        """
        verify ECDSA signature (r, s)
        """
        return self.public_key().verify(signature, message, hasher)

    def sign_recoverable(self, message: bytes, hasher: Callable[[bytes], bytes] = hash256) -> Tuple[int, int, int]:
        """
        :returns: Recoverable ECDSA signature, aka compact signature, in format (recovery_id, r, s)
        """
        e = int.from_bytes(hasher(message), 'big')
        recovery_id, r, s = 0, 0, 0
        while not r or not s:
            k = PrivateKey()
            # recovery id
            # 0x00 - k.x < curve.n and k.y is even
            # 0x01 - k.x < curve.n and k.y is odd
            # 0x10 - k.x > curve.n and k.y is even
            # 0x11 - k.x > curve.n and k.y is odd
            recovery_id = 0 | 2 if k.public_key().point.x > curve.n else 0 | k.public_key().point.y % 2
            r = k.public_key().point.x % curve.n
            s = ((e + r * self.key) * modular_inverse(k.key, curve.n)) % curve.n
        return recovery_id, r, s

    def verify_recoverable(self, signature: Tuple[int, int, int], message: bytes, hasher: Callable[[bytes], bytes] = hash256) -> bool:
        """
        verify recoverable ECDSA signature (recovery_id, r, s)
        """
        return self.public_key().verify_recoverable(signature, message, hasher)

    def sign_text(self, text: str) -> Tuple[str, str]:
        """sign arbitrary text with bitcoin private key
        :returns: (p2pkh_address, serialized_recoverable_ecdsa_signature)
        """
        message: bytes = text_digest(text)
        return self.address(), serialize_ecdsa_recoverable(self.sign_recoverable(message), self.compressed)


def verify_signed_text(text: str, address: str, signature: str, hasher: Callable[[bytes], bytes] = hash256) -> bool:
    """
    verify signed arbitrary text
    """
    message: bytes = text_digest(text)
    recoverable_signature, compressed = deserialize_ecdsa_recoverable(signature)
    _, r, s = recoverable_signature
    public_key = recover_public_key(recoverable_signature, message, hasher)
    return public_key.verify((r, s), message, hasher) and public_key.address(compressed=compressed) == address


def recover_public_key(signature: [int, int, int], message: bytes, hasher: Callable[[bytes], bytes] = hash256) -> PublicKey:
    """
    recover public key from the recoverable ECDSA signature
    """
    recovery_id, r, s = signature
    # calculate the public key (K) corresponding to the ephemeral private key (k) used when signing
    k_x = r + (curve.n if recovery_id >= 2 else 0)
    k_y = get_y(k_x, recovery_id % 2 == 0)
    k_point = Point(k_x, k_y)
    # calculate the public key (A) corresponding to the user private key (a) used when signing
    # A = (sK - eG) / r
    e = int.from_bytes(hasher(message), 'big')
    mod_inv_r = modular_inverse(r, curve.n)
    a_point = add(multiply(mod_inv_r * s, k_point), multiply(mod_inv_r * (-e % curve.n), curve.g))
    return PublicKey(a_point)


Key = PrivateKey
