import pytest

from bsvlib.constants import SIGHASH
from bsvlib.hash import hash256
from bsvlib.keys import Key
from bsvlib.script.script import Script
from bsvlib.script.type import P2pkhScriptType
from bsvlib.transaction.transaction import TxOutput, Transaction
from bsvlib.transaction.unspent import Unspent
from bsvlib.utils import encode_pushdata

digest1 = bytes.fromhex(
    '01000000'
    'ae4b0ed7fb33ec9d5c567520f8cf5f688207f28d5c2f2225c5fe62f7f17c0a25'
    '3bb13029ce7b1f559ef5e747fcac439f1455a2ec7c5f09b72290795e70665044'
    '48dd1f8e77b4a6a75e9b0d0908b25f56b8c98ce37d1fb5ada534d49d0957bcd201000000'
    '1976a9146a176cd51593e00542b8e1958b7da2be97452d0588ac'
    'e803000000000000'
    'ffffffff'
    '048129b26f1d89828c88cdcd472f8f20927822ab7a3d6532cb921c4019f51301'
    '00000000'
    '41000000'
)
digest2 = bytes.fromhex(
    '01000000'
    'ee2851915c957b7187967dabb54f32c00964c689285d3b73e7b2b92e30723c88'
    '752adad0a7b9ceca853768aebb6965eca126a62965f698a0c1bc43d83db632ad'
    '48dd1f8e77b4a6a75e9b0d0908b25f56b8c98ce37d1fb5ada534d49d0957bcd202000000'
    '1976a9146a176cd51593e00542b8e1958b7da2be97452d0588ace'
    '803000000000000'
    'ffffffff'
    'd67a44dde8ee744b7d73b50a3b3a887cb3321d6e16025273f760046c35a265fd'
    '00000000'
    '41000000'
)
digest3 = bytes.fromhex(
    '01000000'
    'ee2851915c957b7187967dabb54f32c00964c689285d3b73e7b2b92e30723c88'
    '752adad0a7b9ceca853768aebb6965eca126a62965f698a0c1bc43d83db632ad'
    'e4c1a33b3a7ca18ef1d6030c6ec222902195f186cb864e09bc1db08b3ea5c1fc00000000'
    '1976a9146a176cd51593e00542b8e1958b7da2be97452d0588ace'
    '803000000000000'
    'ffffffff'
    'd67a44dde8ee744b7d73b50a3b3a887cb3321d6e16025273f760046c35a265fd'
    '00000000'
    '41000000'
)


def test_output():
    assert TxOutput(['123', '456']).locking_script == Script('006a' + '03313233' + '03343536')

    with pytest.raises(TypeError, match=r'unsupported transaction output type'):
        # noinspection PyTypeChecker
        TxOutput(1)


def test_digest():
    address = '1AfxgwYJrBgriZDLryfyKuSdBsi59jeBX9'
    # https://whatsonchain.com/tx/4674da699de44c9c5d182870207ba89e5ccf395e5101dab6b0900bbf2f3b16cb
    expected_digest = [digest1]
    t: Transaction = Transaction()
    t.add_input(Unspent(txid='d2bc57099dd434a5adb51f7de38cc9b8565fb208090d9b5ea7a6b4778e1fdd48', vout=1, satoshi=1000, address=address))
    t.add_output(TxOutput(out='1JDZRGf5fPjGTpqLNwjHFFZnagcZbwDsxw', satoshi=800))
    assert t.digests() == expected_digest

    # https://whatsonchain.com/tx/c04bbd007ad3987f9b2ea8534175b5e436e43d64471bf32139b5851adf9f477e
    expected_digest = [digest2, digest3]
    t: Transaction = Transaction()
    t.add_inputs([
        Unspent(txid='d2bc57099dd434a5adb51f7de38cc9b8565fb208090d9b5ea7a6b4778e1fdd48', vout=2, satoshi=1000, address=address),
        Unspent(txid='fcc1a53e8bb01dbc094e86cb86f195219022c26e0c03d6f18ea17c3a3ba3c1e4', vout=0, satoshi=1000, address=address),
    ])
    t.add_output(TxOutput(out='18CgRLx9hFZqDZv75J5kED7ANnDriwvpi1', satoshi=1700))
    assert t.digest(0) == expected_digest[0]
    assert t.digest(1) == expected_digest[1]


def test_transaction():
    address = '1AfxgwYJrBgriZDLryfyKuSdBsi59jeBX9'
    t = Transaction()
    t.add_input(Unspent(txid='d2bc57099dd434a5adb51f7de38cc9b8565fb208090d9b5ea7a6b4778e1fdd48', vout=1, satoshi=1000, address=address))
    t.add_output(TxOutput(out='1JDZRGf5fPjGTpqLNwjHFFZnagcZbwDsxw', satoshi=800))

    signature = bytes.fromhex('304402207e2c6eb8c4b20e251a71c580373a2836e209c50726e5f8b0f4f59f8af00eee1a022019ae1690e2eb4455add6ca5b86695d65d3261d914bc1d7abb40b188c7f46c9a5')
    sighash = bytes.fromhex('41')
    public_key = bytes.fromhex('02e46dcd7991e5a4bd642739249b0158312e1aee56a60fd1bf622172ffe65bd789')
    t.tx_inputs[0].unlocking_script = Script(encode_pushdata(signature + sighash) + encode_pushdata(public_key))

    assert t.txid() == '4674da699de44c9c5d182870207ba89e5ccf395e5101dab6b0900bbf2f3b16cb'
    assert t.fee() == 200
    assert t.byte_length() == 191

    t.tx_inputs[0].sighash = SIGHASH.NONE_ANYONECANPAY_FORKID
    assert t.digest(0) == t._digest(t.tx_inputs[0], b'\x00' * 32, b'\x00' * 32, b'\x00' * 32)
    t.tx_inputs[0].sighash = SIGHASH.SINGLE_ANYONECANPAY_FORKID
    assert t.digest(0) == t._digest(t.tx_inputs[0], b'\x00' * 32, b'\x00' * 32, hash256(t.tx_outputs[0].serialize()))

    with pytest.raises(ValueError, match=r"can't estimate byte length"):
        t.estimated_fee()
    t.tx_inputs[0].private_keys = [Key('L5agPjZKceSTkhqZF2dmFptT5LFrbr6ZGPvP7u4A6dvhTrr71WZ9')]
    assert t.estimated_fee() == 96

    t.add_change()
    # nothing happened
    assert len(t.tx_outputs) == 1

    t.tx_outputs[0].satoshi = 100
    t.add_change(address)
    # 1-2 transaction 226 bytes --> fee 113 satoshi --> 787 left
    assert len(t.tx_outputs) == 2
    assert t.tx_outputs[1].locking_script == P2pkhScriptType.locking(address)
    assert t.tx_outputs[1].satoshi == 787

    t.tx_outputs.pop()
    t.add_change()
    assert len(t.tx_outputs) == 2
    assert t.tx_outputs[1].locking_script == P2pkhScriptType.locking(address)
    assert t.tx_outputs[1].satoshi == 787

def test_transaction_unserialize():
    t = Transaction()
    t.unserialize(bytes.fromhex("02000000031f5c38dfcf6f1a5f5a87c416076d392c87e6d41970d5ad5e477a02d66bde97580000000000ffffffff7cca453133921c50d5025878f7f738d1df891fd359763331935784cf6b9c82bf1200000000fffffffffccd319e04a996c96cfc0bf4c07539aa90bd0b1a700ef72fae535d6504f9a6220100000000ffffffff0280a81201000000001976a9141fc11f39be1729bf973a7ab6a615ca4729d6457488ac0084d717000000001976a914f2d4db28cad6502226ee484ae24505c2885cb12d88ac00000000"))

    assert t.txid() == "fe7d174f42dce0cffa7a527e9bc8368956057619ec817648f6138b98f2533e8f"
    assert t.version == 2
    assert t.locktime == 0
    assert len(t.tx_inputs) == 3
    assert t.tx_inputs[0].txid == "5897de6bd6027a475eadd57019d4e6872c396d0716c4875a5f1a6fcfdf385c1f"
    assert t.tx_inputs[0].vout == 0
    assert str(t.tx_inputs[0].unlocking_script) == "" 
    assert t.tx_inputs[0].sequence == 4294967295
    assert len(t.tx_outputs) == 2
    assert t.tx_outputs[0].satoshi == 18000000
    assert t.tx_outputs[0].locking_script.hex() == "76a9141fc11f39be1729bf973a7ab6a615ca4729d6457488ac"