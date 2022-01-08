import pytest

from bsvlib.constants import Chain
from bsvlib.utils import decode_p2pkh_address, decode_wif
from bsvlib.utils import unsigned_to_varint


def test_unsigned_to_varint():
    with pytest.raises(OverflowError):
        unsigned_to_varint(-1)

    assert unsigned_to_varint(0) == bytes.fromhex('00')
    assert unsigned_to_varint(0xfc) == bytes.fromhex('fc')

    assert unsigned_to_varint(0xfd) == bytes.fromhex('fdfd00')
    assert unsigned_to_varint(0xabcd) == bytes.fromhex('fdcdab')

    assert unsigned_to_varint(0x010000) == bytes.fromhex('fe00000100')
    assert unsigned_to_varint(0x12345678) == bytes.fromhex('fe78563412')

    assert unsigned_to_varint(0x0100000000) == bytes.fromhex('ff0000000001000000')
    assert unsigned_to_varint(0x1234567890abcdef) == bytes.fromhex('ffefcdab9078563412')

    with pytest.raises(OverflowError):
        unsigned_to_varint(0x010000000000000000)


def test_decode_p2pkh_address():
    assert decode_p2pkh_address('1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa') == (bytes.fromhex('62e907b15cbf27d5425399ebf6f0fb50ebb88f18'), Chain.MAIN)
    assert decode_p2pkh_address('moEoqh2ZfYU8jN5EG6ERw6E3DmwnkuTdBC') == (bytes.fromhex('54b34b1ba228ba1d75dca5a40a114dc0f13a2687'), Chain.TEST)


def test_decode_wif():
    private_key_bytes = bytes.fromhex('f97c89aaacf0cd2e47ddbacc97dae1f88bec49106ac37716c451dcdd008a4b62')
    wif_compressed_main = 'L5agPjZKceSTkhqZF2dmFptT5LFrbr6ZGPvP7u4A6dvhTrr71WZ9'
    wif_uncompressed_main = '5KiANv9EHEU4o9oLzZ6A7z4xJJ3uvfK2RLEubBtTz1fSwAbpJ2U'
    wif_compressed_test = 'cVwfreZB3i8iv9JpdSStd9PWhZZGGJCFLS4rEKWfbkahibwhticA'
    wif_uncompressed_test = '93UnxexmsTYCmDJdctz4zacuwxQd5prDmH6rfpEyKkQViAVA3me'

    assert decode_wif(wif_compressed_main) == (private_key_bytes, True, Chain.MAIN)
    assert decode_wif(wif_uncompressed_main) == (private_key_bytes, False, Chain.MAIN)
    assert decode_wif(wif_compressed_test) == (private_key_bytes, True, Chain.TEST)
    assert decode_wif(wif_uncompressed_test) == (private_key_bytes, False, Chain.TEST)
