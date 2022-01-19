import hashlib

import ecdsa
import pytest

from bsvlib.constants import Chain
from bsvlib.curve import Point
from bsvlib.hash import sha256
from bsvlib.keys import PrivateKey, PublicKey, verify_signed_text
from bsvlib.script.type import P2pkhScriptType
from bsvlib.utils import deserialize_ecdsa_der, deserialize_ecdsa_recoverable, text_digest, serialize_ecdsa_der
from .test_transaction import digest1, digest2, digest3

private_key_hex = 'f97c89aaacf0cd2e47ddbacc97dae1f88bec49106ac37716c451dcdd008a4b62'
private_key_bytes = bytes.fromhex(private_key_hex)
private_key_int = int(private_key_hex, 16)
private_key = PrivateKey(private_key_int)

x = 'e46dcd7991e5a4bd642739249b0158312e1aee56a60fd1bf622172ffe65bd789'
y = '97693d32c540ac253de7a3dc73f7e4ba7b38d2dc1ecc8e07920b496fb107d6b2'
point = Point(int(x, 16), int(y, 16))
public_key = PublicKey(point)

address_compressed_main = '1AfxgwYJrBgriZDLryfyKuSdBsi59jeBX9'
address_uncompressed_main = '1BVHzn1J8VZWRuVWbPrj2Szx1j7hHdt5zP'
address_compressed_test = 'mqBuyzdHfD87VfgxaYeM9pex3sJn4ihYHY'
address_uncompressed_test = 'mr1FHq6GwWzmD1y8Jxq6rNDGsiiQ9caF7r'


def test_public_key():
    public_key_compressed = f'02{x}'
    public_key_uncompressed = f'04{x}{y}'

    assert public_key.point == point
    assert public_key.hex() == public_key_compressed
    assert public_key.hex(compressed=True) == public_key_compressed
    assert public_key.hex(compressed=False) == public_key_uncompressed

    assert public_key.address() == address_compressed_main
    assert public_key.address(compressed=True, chain=Chain.MAIN) == address_compressed_main
    assert public_key.address(compressed=False, chain=Chain.MAIN) == address_uncompressed_main
    assert public_key.address(compressed=True, chain=Chain.TEST) == address_compressed_test
    assert public_key.address(compressed=False, chain=Chain.TEST) == address_uncompressed_test

    assert PublicKey(public_key_compressed) == public_key
    assert PublicKey(public_key_compressed).address() == address_compressed_main

    assert PublicKey(public_key_uncompressed) == public_key
    assert PublicKey(public_key_uncompressed).address() == address_uncompressed_main

    assert PublicKey(bytes.fromhex(public_key_compressed)) == public_key

    with pytest.raises(TypeError, match=r'unsupported public key type'):
        # noinspection PyTypeChecker
        PublicKey(1.23)

    with pytest.raises(ValueError, match=r'invalid public key prefix'):
        PublicKey(f'05{x}')


def test_private_key():
    assert private_key.public_key() == public_key
    assert private_key.hex() == private_key_hex
    assert private_key.serialize() == private_key_bytes
    assert private_key.int() == private_key_int
    assert private_key.locking_script() == P2pkhScriptType.locking(address_compressed_main)

    priv_key_wif_compressed_main = 'L5agPjZKceSTkhqZF2dmFptT5LFrbr6ZGPvP7u4A6dvhTrr71WZ9'
    priv_key_wif_uncompressed_main = '5KiANv9EHEU4o9oLzZ6A7z4xJJ3uvfK2RLEubBtTz1fSwAbpJ2U'
    priv_key_wif_compressed_test = 'cVwfreZB3i8iv9JpdSStd9PWhZZGGJCFLS4rEKWfbkahibwhticA'
    priv_key_wif_uncompressed_test = '93UnxexmsTYCmDJdctz4zacuwxQd5prDmH6rfpEyKkQViAVA3me'

    assert private_key.wif() == priv_key_wif_compressed_main
    assert private_key.wif(compressed=True, chain=Chain.MAIN) == priv_key_wif_compressed_main
    assert private_key.wif(compressed=False, chain=Chain.MAIN) == priv_key_wif_uncompressed_main
    assert private_key.wif(compressed=True, chain=Chain.TEST) == priv_key_wif_compressed_test
    assert private_key.wif(compressed=False, chain=Chain.TEST) == priv_key_wif_uncompressed_test

    assert PrivateKey(private_key_bytes) == private_key
    assert PrivateKey(priv_key_wif_compressed_main) == private_key
    assert PrivateKey(priv_key_wif_uncompressed_main) == private_key
    assert PrivateKey(priv_key_wif_compressed_test) == private_key
    assert PrivateKey(priv_key_wif_uncompressed_test) == private_key

    assert PrivateKey(private_key_bytes).wif() == priv_key_wif_compressed_main
    assert PrivateKey(private_key_bytes).address() == address_compressed_main

    assert PrivateKey(priv_key_wif_compressed_main).wif() == priv_key_wif_compressed_main
    assert PrivateKey(priv_key_wif_compressed_main).address() == address_compressed_main

    assert PrivateKey(priv_key_wif_uncompressed_main).wif() == priv_key_wif_uncompressed_main
    assert PrivateKey(priv_key_wif_uncompressed_main).address() == address_uncompressed_main

    assert PrivateKey(priv_key_wif_compressed_test).wif() == priv_key_wif_compressed_test
    assert PrivateKey(priv_key_wif_compressed_test).address() == address_compressed_test

    assert PrivateKey(priv_key_wif_uncompressed_test).wif() == priv_key_wif_uncompressed_test
    assert PrivateKey(priv_key_wif_uncompressed_test).address() == address_uncompressed_test

    with pytest.raises(TypeError, match=r'unsupported private key type'):
        # noinspection PyTypeChecker
        PrivateKey(1.23)


def test_verify():
    # https://whatsonchain.com/tx/4674da699de44c9c5d182870207ba89e5ccf395e5101dab6b0900bbf2f3b16cb
    der: bytes = bytes.fromhex('304402207e2c6eb8c4b20e251a71c580373a2836e209c50726e5f8b0f4f59f8af00eee1a022019ae1690e2eb4455add6ca5b86695d65d3261d914bc1d7abb40b188c7f46c9a5')
    assert private_key.verify(deserialize_ecdsa_der(der), digest1)

    # https://whatsonchain.com/tx/c04bbd007ad3987f9b2ea8534175b5e436e43d64471bf32139b5851adf9f477e
    der: bytes = bytes.fromhex('3043022053b1f5a28a011c60614401eeef88e49c676a098ce36d95ded1b42667f40efa37021f4de6703f8c74b0ce5dad617c00d1fb99580beb7972bf681e7215911c3648de')
    assert private_key.verify(deserialize_ecdsa_der(der), digest2)
    der: bytes = bytes.fromhex('3045022100b9f293781ae1e269591df779dbadb41b9971d325d7b8f83d883fb55f2cb3ff7602202fe1e822628d85b0f52966602d0e153be411980d54884fa48a41d6fc32b4e9f5')
    assert private_key.verify(deserialize_ecdsa_der(der), digest3)


def test_sign():
    # ecdsa
    message: bytes = b'hello world'
    signature = private_key.sign(message)
    der: bytes = serialize_ecdsa_der(signature)
    vk = ecdsa.VerifyingKey.from_string(public_key.serialize(), curve=ecdsa.SECP256k1)
    assert vk.verify(signature=der, data=sha256(message), hashfunc=hashlib.sha256, sigdecode=ecdsa.util.sigdecode_der)

    # recoverable ecdsa
    text = 'hello world'
    address, signature = private_key.sign_text(text)
    assert verify_signed_text(text, address, signature)

    message: bytes = text_digest(text)
    recoverable_signature, _ = deserialize_ecdsa_recoverable(signature)
    assert private_key.verify_recoverable(recoverable_signature, message)

    address, signature = PrivateKey('5KiANv9EHEU4o9oLzZ6A7z4xJJ3uvfK2RLEubBtTz1fSwAbpJ2U').sign_text(text)
    assert verify_signed_text(text, address, signature)
