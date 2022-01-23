import hmac
from hashlib import sha512
from typing import Union

from ..base58 import base58check_decode, base58check_encode
from ..constants import Chain, XKEY_BYTE_LENGTH, XKEY_PREFIX_LIST, PUBLIC_KEY_COMPRESSED_PREFIX_LIST
from ..constants import XPUB_PREFIX_CHAIN_DICT, XPRV_PREFIX_CHAIN_DICT, CHAIN_XPUB_PREFIX_DICT, CHAIN_XPRV_PREFIX_DICT
from ..curve import curve, add, multiply
from ..keys import PublicKey, PrivateKey


class XKey:
    """
    [  : 4] prefix
    [ 4: 5] depth
    [ 5: 9] parent public key fingerprint
    [ 9:13] child index
    [13:45] chain code
    [45:78] key (private/public)
    """

    def __init__(self, xkey: Union[str, bytes]):
        if isinstance(xkey, str):
            self.payload: bytes = base58check_decode(xkey)
        elif isinstance(xkey, bytes):
            self.payload: bytes = xkey
        else:
            raise TypeError('unsupported extended key type')

        assert len(self.payload) == XKEY_BYTE_LENGTH, 'invalid extended key length'
        self.prefix: bytes = self.payload[:4]
        self.depth: int = self.payload[4]
        self.fingerprint: bytes = self.payload[5:9]
        self.index: int = int.from_bytes(self.payload[9:13], 'big')
        self.chain_code: bytes = self.payload[13:45]
        self.key_bytes: bytes = self.payload[45:]
        assert self.prefix in XKEY_PREFIX_LIST, 'invalid extended key prefix'

    def __eq__(self, o: object) -> bool:
        if isinstance(o, XKey):
            return self.payload == o.payload
        return super().__eq__(o)  # pragma: no cover

    def __str__(self) -> str:
        return base58check_encode(self.payload)


class XPub(XKey):

    def __init__(self, xpub: Union[str, bytes]):
        super().__init__(xpub)
        self.chain: Chain = XPUB_PREFIX_CHAIN_DICT.get(self.prefix)
        assert self.chain, 'unknown xpub prefix'
        assert self.payload[45:46] in PUBLIC_KEY_COMPRESSED_PREFIX_LIST, 'invalid public key in xpub'
        self.key: PublicKey = PublicKey(self.key_bytes)

    def ckd(self, index: Union[int, str, bytes]) -> 'XPub':
        if isinstance(index, int):
            index = index.to_bytes(4, 'big')
        elif isinstance(index, str):
            index = bytes.fromhex(index)
        assert len(index) == 4, 'index should be a 4 bytes integer'
        assert index[0] < 0x80, "can't make hardened derivation from xpub"

        payload: bytes = self.prefix
        payload += (self.depth + 1).to_bytes(1, 'big')
        payload += self.key.hash160()[:4]
        payload += index

        h: bytes = hmac.new(self.chain_code, self.key.serialize() + index, sha512).digest()
        offset: int = int.from_bytes(h[:32], 'big')
        child: PublicKey = PublicKey(add(self.key.point, multiply(offset, curve.g)))

        payload += h[32:]
        payload += child.serialize()

        return XPub(payload)

    def child(self, path: str) -> 'XPub':
        return self.ckd(get_index(path))

    def public_key(self) -> PublicKey:
        return self.key

    def address(self) -> str:
        return self.key.address(chain=self.chain)

    @classmethod
    def from_xprv(cls, xprv: Union[str, bytes, 'XPrv']) -> 'XPub':
        if not isinstance(xprv, XPrv):
            xprv = XPrv(xprv)
        payload: bytes = CHAIN_XPUB_PREFIX_DICT.get(xprv.chain)
        payload += xprv.depth.to_bytes(1, 'big')
        payload += xprv.fingerprint
        payload += xprv.index.to_bytes(4, 'big')
        payload += xprv.chain_code
        payload += xprv.key.public_key().serialize()
        return XPub(payload)


class XPrv(XKey):

    def __init__(self, xprv: Union[str, bytes]):
        super().__init__(xprv)
        self.chain: Chain = XPRV_PREFIX_CHAIN_DICT.get(self.prefix)
        assert self.chain, 'unknown xprv prefix'
        assert self.payload[45] == 0, 'invalid private key in xprv'
        self.key: PrivateKey = PrivateKey(self.key_bytes[1:], chain=self.chain)

    def ckd(self, index: Union[int, str, bytes]) -> 'XPrv':
        if isinstance(index, int):
            index = index.to_bytes(4, 'big')
        elif isinstance(index, str):
            index = bytes.fromhex(index)
        assert len(index) == 4, 'index should be a 4 bytes integer'

        payload: bytes = self.prefix
        payload += (self.depth + 1).to_bytes(1, 'big')
        payload += self.key.public_key().hash160()[:4]
        payload += index

        message: bytes = (self.key.public_key().serialize() if index[0] < 0x80 else self.key_bytes) + index
        h: bytes = hmac.new(self.chain_code, message, sha512).digest()
        offset: int = int.from_bytes(h[:32], 'big')
        child: PrivateKey = PrivateKey((self.key.key + offset) % curve.n)

        payload += h[32:]
        payload += b'\x00' + child.serialize()

        return XPrv(payload)

    def child(self, path: str) -> 'XPrv':
        return self.ckd(get_index(path))

    def xpub(self) -> XPub:
        return XPub.from_xprv(self)

    def private_key(self) -> PrivateKey:
        return self.key

    def public_key(self) -> PublicKey:
        return self.key.public_key()

    def address(self) -> str:
        return self.key.address()

    @classmethod
    def from_seed(cls, seed: Union[str, bytes], chain: Chain = Chain.MAIN):
        if isinstance(seed, str):
            seed = bytes.fromhex(seed)

        payload: bytes = CHAIN_XPRV_PREFIX_DICT.get(chain)
        payload += b'\x00'
        payload += b'\x00\x00\x00\x00'
        payload += b'\x00\x00\x00\x00'

        h: bytes = hmac.new(b'Bitcoin seed', seed, sha512).digest()
        payload += h[32:]
        payload += b'\x00' + h[:32]

        return XPrv(payload)


def get_index(path: str) -> int:
    """
    convert path "0" (normal derivation) or "0'" (hardened derivation) into child index
    """
    assert len(path), 'invalid path'
    hardened: bool = path[-1] == "'"
    index: int = (0x80000000 if hardened else 0) + int(path[:-1] if hardened else path)
    assert 0 <= index < 0xffffffff, 'path out of range'
    return index
