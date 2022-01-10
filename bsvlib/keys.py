from collections import namedtuple
from typing import Optional, Union, Callable

from coincurve import PrivateKey as CcPrivateKey, PublicKey as CcPublicKey

from .base58 import base58check_encode
from .constants import Chain, ADDRESS_CHAIN_PREFIX, WIF_CHAIN_PREFIX, PUBLIC_KEY_COMPRESSED_BYTE_LENGTH
from .hash import hash160, hash256
from .transaction.script import Script
from .utils import decode_wif

Point = namedtuple('Point', ('x', 'y'))


class PublicKey:

    def __init__(self, public_key: Union[str, bytes, Point, CcPublicKey]):
        """
        create public key from hex string, bytes, curve point or CoinCurve public key
        """
        self.compressed = True  # default compressed format public key
        if isinstance(public_key, str):
            # from serialized public key in hex string
            self.key = CcPublicKey(bytes.fromhex(public_key))
            self.compressed = True if len(public_key) == PUBLIC_KEY_COMPRESSED_BYTE_LENGTH * 2 else False
        elif isinstance(public_key, bytes):
            # from serialized public key in bytes
            self.key = CcPublicKey(public_key)
            self.compressed = True if len(public_key) == PUBLIC_KEY_COMPRESSED_BYTE_LENGTH else False
        elif isinstance(public_key, Point):
            # from curve point
            self.key = CcPublicKey.from_point(public_key.x, public_key.y)
        elif isinstance(public_key, CcPublicKey):
            # from CoinCurve public key
            self.key = public_key
        else:
            raise TypeError('unsupported public key type')

    def point(self) -> Point:
        return self.key.point()

    def serialize(self, compressed: Optional[bool] = None) -> bytes:
        compressed = self.compressed if compressed is None else compressed
        return self.key.format(compressed)

    def hex(self, compressed: Optional[bool] = None) -> str:
        return self.serialize(compressed).hex()

    def hash160(self, compressed: Optional[bool] = None) -> bytes:
        return hash160(self.serialize(compressed))

    def locking_script(self, compressed: Optional[bool] = None) -> Script:
        return Script.p2pkh_locking(self.hash160(compressed))

    def address(self, compressed: Optional[bool] = None, chain: Chain = Chain.MAIN) -> str:
        return base58check_encode(ADDRESS_CHAIN_PREFIX.get(chain) + self.hash160(compressed))

    def __eq__(self, o: object) -> bool:
        if isinstance(o, PublicKey):
            return self.key == o.key
        return super().__eq__(o)

    def verify(self, signature: bytes, message: bytes, hasher: Callable[[bytes], bytes] = hash256) -> bool:
        return self.key.verify(signature=signature, message=message, hasher=hasher)


class PrivateKey:

    def __init__(self, private_key: Union[str, int, bytes, CcPrivateKey, None] = None, chain: Optional[Chain] = None):
        """
        create private key from WIF (str), int, bytes, or CoinCurve private key
        random a new private key if None
        """
        self.chain = chain or Chain.MAIN
        self.compressed = True  # default compressed wif
        if private_key is None:
            self.key = CcPrivateKey()
        else:
            if isinstance(private_key, str):
                # from wif
                private_key_bytes, self.compressed, self.chain = decode_wif(private_key)
                self.key = CcPrivateKey(private_key_bytes)
            elif isinstance(private_key, int):
                # from private key as int
                self.key = CcPrivateKey.from_int(private_key)
            elif isinstance(private_key, bytes):
                # from private key integer in bytes
                self.key = CcPrivateKey.from_hex(private_key.hex())
            elif isinstance(private_key, CcPrivateKey):
                # from CoinCurve private key
                self.key = private_key
            else:
                raise TypeError('unsupported private key type')

    def public_key(self) -> PublicKey:
        pk = PublicKey(self.key.public_key)
        pk.compressed = self.compressed
        return pk

    def locking_script(self, compressed: Optional[bool] = None) -> Script:
        compressed = self.compressed if compressed is None else compressed
        return self.public_key().locking_script(compressed)

    def address(self, compressed: Optional[bool] = None, chain: Optional[Chain] = None) -> str:
        compressed = self.compressed if compressed is None else compressed
        chain = chain or self.chain
        return self.public_key().address(compressed, chain)

    def wif(self, compressed: Optional[bool] = None, chain: Optional[Chain] = None) -> str:
        compressed = self.compressed if compressed is None else compressed
        chain = chain or self.chain
        key_bytes = self.key.to_int().to_bytes(32, 'big')
        compressed_bytes = b'\x01' if compressed else b''
        return base58check_encode(WIF_CHAIN_PREFIX.get(chain) + key_bytes + compressed_bytes)

    def int(self) -> int:
        return self.key.to_int()

    def hex(self) -> str:
        return self.key.to_hex()

    def serialize(self) -> bytes:
        return bytes.fromhex(self.hex())

    def __eq__(self, o: object) -> bool:
        if isinstance(o, PrivateKey):
            return self.key == o.key
        return super().__eq__(o)

    def sign(self, message: serialize, hasher: Optional[Callable[[serialize], serialize]] = hash256) -> serialize:
        """
        :returns: ECDSA signature in DER format, compliant with low-s requirement in BIP-62 and BIP-66
        """
        return self.key.sign(message=message, hasher=hasher)

    def verify(self, signature: serialize, message: serialize, hasher: Callable[[serialize], serialize] = hash256) -> bool:
        return self.public_key().verify(signature=signature, message=message, hasher=hasher)


Key = PrivateKey
