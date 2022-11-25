import hmac
from hashlib import sha512
from typing import Union

from ..base58 import base58check_decode, base58check_encode
from ..constants import BIP32_SEED_BYTE_LENGTH
from ..constants import Chain, XKEY_BYTE_LENGTH, XKEY_PREFIX_LIST, PUBLIC_KEY_COMPRESSED_PREFIX_LIST
from ..constants import XPUB_PREFIX_CHAIN_DICT, XPRV_PREFIX_CHAIN_DICT, CHAIN_XPUB_PREFIX_DICT, CHAIN_XPRV_PREFIX_DICT
from ..curve import curve, add, multiply
from ..keys import PublicKey, PrivateKey


class Xkey:
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
        if isinstance(o, Xkey):
            return self.payload == o.payload
        return super().__eq__(o)  # pragma: no cover

    def __str__(self) -> str:
        return base58check_encode(self.payload)

    def __repr__(self) -> str:  # pragma: no cover
        return self.__str__()


class Xpub(Xkey):

    def __init__(self, xpub: Union[str, bytes]):
        super().__init__(xpub)
        self.chain: Chain = XPUB_PREFIX_CHAIN_DICT.get(self.prefix)
        assert self.chain, 'unknown xpub prefix'
        assert self.payload[45:46] in PUBLIC_KEY_COMPRESSED_PREFIX_LIST, 'invalid public key in xpub'
        self.key: PublicKey = PublicKey(self.key_bytes)

    def ckd(self, index: Union[int, str, bytes]) -> 'Xpub':
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
        child: PublicKey = PublicKey(add(self.key.point(), multiply(offset, curve.g)))

        payload += h[32:]
        payload += child.serialize()

        return Xpub(payload)

    def public_key(self) -> PublicKey:
        return self.key

    def address(self) -> str:
        return self.key.address(chain=self.chain)

    @classmethod
    def from_xprv(cls, xprv: Union[str, bytes, 'Xprv']) -> 'Xpub':
        if not isinstance(xprv, Xprv):
            xprv = Xprv(xprv)
        payload: bytes = CHAIN_XPUB_PREFIX_DICT.get(xprv.chain)
        payload += xprv.depth.to_bytes(1, 'big')
        payload += xprv.fingerprint
        payload += xprv.index.to_bytes(4, 'big')
        payload += xprv.chain_code
        payload += xprv.key.public_key().serialize()
        return Xpub(payload)


class Xprv(Xkey):

    def __init__(self, xprv: Union[str, bytes]):
        super().__init__(xprv)
        self.chain: Chain = XPRV_PREFIX_CHAIN_DICT.get(self.prefix)
        assert self.chain, 'unknown xprv prefix'
        assert self.payload[45] == 0, 'invalid private key in xprv'
        self.key: PrivateKey = PrivateKey(self.key_bytes[1:], chain=self.chain)

    def ckd(self, index: Union[int, str, bytes]) -> 'Xprv':
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
        child: PrivateKey = PrivateKey((self.key.int() + offset) % curve.n)

        payload += h[32:]
        payload += b'\x00' + child.serialize()

        return Xprv(payload)

    def xpub(self) -> Xpub:
        return Xpub.from_xprv(self)

    def private_key(self) -> PrivateKey:
        return self.key

    def public_key(self) -> PublicKey:
        return self.key.public_key()

    def address(self) -> str:
        return self.key.address()

    @classmethod
    def from_seed(cls, seed: Union[str, bytes], chain: Chain = Chain.MAIN):
        """
        derive master extended private key from seed
        """
        if isinstance(seed, str):
            seed = bytes.fromhex(seed)
        assert len(seed) == BIP32_SEED_BYTE_LENGTH, 'invalid seed byte length'

        payload: bytes = CHAIN_XPRV_PREFIX_DICT.get(chain)
        payload += b'\x00'
        payload += b'\x00\x00\x00\x00'
        payload += b'\x00\x00\x00\x00'

        h: bytes = hmac.new(b'Bitcoin seed', seed, sha512).digest()
        payload += h[32:]
        payload += b'\x00' + h[:32]

        return Xprv(payload)


def step_to_index(step: Union[str, int]) -> int:
    """
    convert step (sub path) "xx" (normal derivation) or "xx'" (hardened derivation) into child index
    """
    assert type(step).__name__ in ['str', 'int'], 'unsupported step type'
    if isinstance(step, str):
        assert len(step), 'invalid step'
        hardened: bool = step[-1] == "'"
        index: int = (0x80000000 if hardened else 0) + int(step[:-1] if hardened else step)
    else:
        index: int = step
    assert 0 <= index < 0xffffffff, 'step out of range'
    return index


def ckd(xkey: Union[Xprv, Xpub], path: str) -> Union[Xprv, Xpub]:
    """
    derive an extended key according to path like "m/44'/0'/1'/0/10" (absolute) or "./0/10" (relative)
    """
    steps = path.strip(' ').strip('/').split('/')
    assert steps and steps[0] in ['m', '.']

    if steps[0] == 'm':
        # should be master key
        assert xkey.depth == 0 and xkey.fingerprint == b'\x00\x00\x00\x00' and xkey.index == 0, 'absolute path for non-master key'

    child = xkey
    for step in steps[1:]:
        child = child.ckd(step_to_index(step))
    return child


def master_xprv_from_seed(seed: Union[str, bytes], chain: Chain = Chain.MAIN) -> Xprv:
    return Xprv.from_seed(seed, chain)
