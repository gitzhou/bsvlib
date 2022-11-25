import hashlib
import hmac
from base64 import b64encode, b64decode
from typing import Optional, Union, Callable, Tuple

from coincurve import PrivateKey as CcPrivateKey, PublicKey as CcPublicKey

from .aes import aes_decrypt_with_iv
from .aes import aes_encrypt_with_iv
from .base58 import base58check_encode
from .constants import Chain, CHAIN_ADDRESS_PREFIX_DICT, CHAIN_WIF_PREFIX_DICT
from .constants import PUBLIC_KEY_COMPRESSED_PREFIX_LIST
from .curve import Point
from .hash import hash160, hash256
from .script.script import Script
from .script.type import P2pkhScriptType
from .utils import decode_wif, text_digest, stringify_ecdsa_recoverable, unstringify_ecdsa_recoverable
from .utils import deserialize_ecdsa_recoverable, serialize_ecdsa_der


class PublicKey:

    def __init__(self, public_key: Union[str, bytes, Point, CcPublicKey]):
        """
        create public key from serialized hex string or bytes, or curve point, or CoinCurve public key
        """
        self.compressed: bool = True  # use compressed format public key by default
        if isinstance(public_key, Point):
            # from curve point
            self.key: CcPublicKey = CcPublicKey.from_point(public_key.x, public_key.y)
        elif isinstance(public_key, CcPublicKey):
            # from CoinCurve public key
            self.key: CcPublicKey = public_key
        else:
            if isinstance(public_key, str):
                # from serialized public key in hex string
                pk: bytes = bytes.fromhex(public_key)
            elif isinstance(public_key, bytes):
                # from serialized public key in bytes
                pk: bytes = public_key
            else:
                raise TypeError('unsupported public key type')
            # here we have serialized public key in bytes
            self.key: CcPublicKey = CcPublicKey(pk)
            self.compressed: bool = pk[:1] in PUBLIC_KEY_COMPRESSED_PREFIX_LIST

    def point(self) -> Point:
        return Point(*self.key.point())

    def serialize(self, compressed: Optional[bool] = None) -> bytes:
        compressed = self.compressed if compressed is None else compressed
        return self.key.format(compressed)

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

    def verify(self, signature: bytes, message: bytes, hasher: Optional[Callable[[bytes], bytes]] = hash256) -> bool:
        """
        verify serialized ECDSA signature in bitcoin strict DER (low-s) format
        """
        return self.key.verify(signature, message, hasher)

    def verify_recoverable(self, signature: bytes, message: bytes, hasher: Optional[Callable[[bytes], bytes]] = hash256) -> bool:
        """
        verify serialized recoverable ECDSA signature in format "r (32 bytes) + s (32 bytes) + recovery_id (1 byte)"
        """
        r, s, _ = deserialize_ecdsa_recoverable(signature)
        der = serialize_ecdsa_der((r, s))
        return self.verify(der, message, hasher) and self == recover_public_key(signature, message, hasher)

    def ecdh_key(self, key: 'PrivateKey') -> bytes:
        return PublicKey(self.key.multiply(key.serialize())).serialize()

    def encrypt(self, message: bytes) -> bytes:
        """
        Electrum ECIES (aka BIE1) encryption
        """
        # generate an ephemeral EC private key in order to derive shared secret (ECDH key)
        ephemeral_private_key = PrivateKey()
        # derive ECDH key
        ecdh_key: bytes = self.ecdh_key(ephemeral_private_key)
        # SHA512(ECDH_KEY), then we have
        # key_e and iv used in AES, key_m used in HMAC.SHA256
        key: bytes = hashlib.sha512(ecdh_key).digest()
        iv, key_e, key_m = key[0:16], key[16:32], key[32:]
        # make AES encryption
        cipher: bytes = aes_encrypt_with_iv(key_e, iv, message)
        # encrypted = magic_bytes (4 bytes) + ephemeral_public_key (33 bytes) + cipher (16 bytes at least)
        encrypted: bytes = 'BIE1'.encode('utf-8') + ephemeral_private_key.public_key().serialize() + cipher
        # mac = HMAC_SHA256(encrypted), 32 bytes
        mac: bytes = hmac.new(key_m, encrypted, hashlib.sha256).digest()
        # give out encrypted + mac
        return encrypted + mac

    def encrypt_text(self, text: str) -> str:
        """
        :returns: BIE1 encrypted text, base64 encoded
        """
        message: bytes = text.encode('utf-8')
        return b64encode(self.encrypt(message)).decode('ascii')

    def __eq__(self, o: object) -> bool:
        if isinstance(o, PublicKey):
            return self.key == o.key
        return super().__eq__(o)  # pragma: no cover

    def __str__(self) -> str:  # pragma: no cover
        return f'<PublicKey hex={self.hex()}>'

    def __repr__(self) -> str:  # pragma: no cover
        return self.__str__()


class PrivateKey:

    def __init__(self, private_key: Union[str, int, bytes, CcPrivateKey, None] = None, chain: Optional[Chain] = None):
        """
        create private key from WIF (str), or int, or bytes, or CoinCurve private key
        random a new private key if None
        """
        self.chain: Chain = chain or Chain.MAIN
        self.compressed: bool = True  # use compressed WIF by default
        if private_key is None:
            # create a new private key
            self.key: CcPrivateKey = CcPrivateKey()
        elif isinstance(private_key, CcPrivateKey):
            # from CoinCurve private key
            self.key: CcPrivateKey = private_key
        else:
            if isinstance(private_key, str):
                # from wif
                private_key_bytes, self.compressed, self.chain = decode_wif(private_key)
                self.key: CcPrivateKey = CcPrivateKey(private_key_bytes)
            elif isinstance(private_key, int):
                # from private key as int
                self.key: CcPrivateKey = CcPrivateKey.from_int(private_key)
            elif isinstance(private_key, bytes):
                # from private key integer in bytes
                self.key: CcPrivateKey = CcPrivateKey(private_key)
            else:
                raise TypeError('unsupported private key type')

    def public_key(self) -> PublicKey:
        return PublicKey(self.key.public_key.format(self.compressed))

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
        return self.key.to_int()

    def serialize(self) -> bytes:
        return self.key.secret

    def hex(self) -> str:
        return self.serialize().hex()

    def der(self) -> bytes:  # pragma: no cover
        return self.key.to_der()

    def pem(self) -> bytes:  # pragma: no cover
        return self.key.to_pem()

    def sign(self, message: bytes, hasher: Optional[Callable[[bytes], bytes]] = hash256) -> bytes:
        """
        :returns: ECDSA signature in bitcoin strict DER (low-s) format
        """
        return self.key.sign(message, hasher)

    def verify(self, signature: bytes, message: bytes, hasher: Optional[Callable[[bytes], bytes]] = hash256) -> bool:
        """
        verify ECDSA signature in bitcoin strict DER (low-s) format
        """
        return self.public_key().verify(signature, message, hasher)

    def sign_recoverable(self, message: bytes, hasher: Optional[Callable[[bytes], bytes]] = hash256) -> bytes:
        """
        :returns: serialized recoverable ECDSA signature (aka compact signature) in format
                    r (32 bytes) + s (32 bytes) + recovery_id (1 byte)
        """
        return self.key.sign_recoverable(message, hasher)

    def verify_recoverable(self, signature: bytes, message: bytes, hasher: Optional[Callable[[bytes], bytes]] = hash256) -> bool:
        """
        verify serialized recoverable ECDSA signature in format "r (32 bytes) + s (32 bytes) + recovery_id (1 byte)"
        """
        return self.public_key().verify_recoverable(signature, message, hasher)

    def sign_text(self, text: str) -> Tuple[str, str]:
        """sign arbitrary text with bitcoin private key
        :returns: (p2pkh_address, stringified_recoverable_ecdsa_signature)
        """
        message: bytes = text_digest(text)
        return self.address(), stringify_ecdsa_recoverable(self.sign_recoverable(message), self.compressed)

    def ecdh_key(self, key: PublicKey) -> bytes:
        return PublicKey(key.key.multiply(self.serialize())).serialize()

    def decrypt(self, message: bytes) -> bytes:
        """
        Electrum ECIES (aka BIE1) decryption
        """
        assert len(message) >= 85, 'invalid encrypted length'
        encrypted, mac = message[:-32], message[-32:]
        # encrypted = magic_bytes (4 bytes) + ephemeral_public_key (33 bytes) + cipher_text (16 bytes at least)
        magic_bytes, ephemeral_public_key, cipher = encrypted[:4], PublicKey(encrypted[4:37]), encrypted[37:]
        assert magic_bytes.decode('utf-8') == 'BIE1', 'invalid magic bytes'
        # restore ECDH key
        ecdh_key = self.ecdh_key(ephemeral_public_key)
        # restore iv, key_e, key_m
        key = hashlib.sha512(ecdh_key).digest()
        iv, key_e, key_m = key[0:16], key[16:32], key[32:]
        # verify mac
        assert hmac.new(key_m, encrypted, hashlib.sha256).digest().hex() == mac.hex(), 'incorrect hmac checksum'
        # make the AES decryption
        return aes_decrypt_with_iv(key_e, iv, cipher)

    def decrypt_text(self, text: str) -> str:
        """
        decrypt BIE1 encrypted, base64 encoded text
        """
        message: bytes = b64decode(text)
        return self.decrypt(message).decode('utf-8')

    def encrypt(self, message: bytes) -> bytes:  # pragma: no cover
        """
        Electrum ECIES (aka BIE1) encryption
        """
        return self.public_key().encrypt(message)

    def encrypt_text(self, text: str) -> str:  # pragma: no cover
        """
        :returns: BIE1 encrypted text, base64 encoded
        """
        return self.public_key().encrypt_text(text)

    def __eq__(self, o: object) -> bool:
        if isinstance(o, PrivateKey):
            return self.key == o.key
        return super().__eq__(o)  # pragma: no cover

    def __str__(self) -> str:  # pragma: no cover
        return f'<PrivateKey wif={self.wif()} int={self.int()}>'

    def __repr__(self) -> str:  # pragma: no cover
        return self.__str__()

    @classmethod
    def from_hex(cls, octets: Union[str, bytes]) -> 'PrivateKey':
        b: bytes = octets if isinstance(octets, bytes) else bytes.fromhex(octets)
        return PrivateKey(CcPrivateKey(b))

    @classmethod
    def from_der(cls, octets: Union[str, bytes]) -> 'PrivateKey':  # pragma: no cover
        b: bytes = octets if isinstance(octets, bytes) else bytes.fromhex(octets)
        return PrivateKey(CcPrivateKey.from_der(b))

    @classmethod
    def from_pem(cls, octets: Union[str, bytes]) -> 'PrivateKey':  # pragma: no cover
        b: bytes = octets if isinstance(octets, bytes) else bytes.fromhex(octets)
        return PrivateKey(CcPrivateKey.from_pem(b))


def verify_signed_text(text: str, address: str, signature: str, hasher: Optional[Callable[[bytes], bytes]] = hash256) -> bool:
    """
    verify signed arbitrary text
    """
    serialized_recoverable, compressed = unstringify_ecdsa_recoverable(signature)
    r, s, _ = deserialize_ecdsa_recoverable(serialized_recoverable)
    message: bytes = text_digest(text)
    public_key: PublicKey = recover_public_key(serialized_recoverable, message, hasher)
    der: bytes = serialize_ecdsa_der((r, s))
    return public_key.verify(der, message, hasher) and public_key.address(compressed=compressed) == address


def recover_public_key(signature: bytes, message: bytes, hasher: Optional[Callable[[bytes], bytes]] = hash256) -> PublicKey:
    """
    recover public key from serialized recoverable ECDSA signature in format
      "r (32 bytes) + s (32 bytes) + recovery_id (1 byte)"
    """
    return PublicKey(CcPublicKey.from_signature_and_message(signature, message, hasher))


Key = PrivateKey
