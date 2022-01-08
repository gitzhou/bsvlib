from bsvlib.transaction.transaction import TxOutput, Transaction
from bsvlib.transaction.unspent import Unspent

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


def test_transaction_digest():
    address = '1AfxgwYJrBgriZDLryfyKuSdBsi59jeBX9'
    # https://whatsonchain.com/tx/4674da699de44c9c5d182870207ba89e5ccf395e5101dab6b0900bbf2f3b16cb
    expected_digest = [digest1]
    t: Transaction = Transaction()
    t.add_input(Unspent(txid='d2bc57099dd434a5adb51f7de38cc9b8565fb208090d9b5ea7a6b4778e1fdd48', vout=1, satoshi=1000, address=address))
    t.add_output(TxOutput(out='1JDZRGf5fPjGTpqLNwjHFFZnagcZbwDsxw', satoshi=800))
    assert t.digest() == expected_digest

    # https://whatsonchain.com/tx/c04bbd007ad3987f9b2ea8534175b5e436e43d64471bf32139b5851adf9f477e
    expected_digest = [digest2, digest3]
    t: Transaction = Transaction()
    t.add_inputs([
        Unspent(txid='d2bc57099dd434a5adb51f7de38cc9b8565fb208090d9b5ea7a6b4778e1fdd48', vout=2, satoshi=1000, address=address),
        Unspent(txid='fcc1a53e8bb01dbc094e86cb86f195219022c26e0c03d6f18ea17c3a3ba3c1e4', vout=0, satoshi=1000, address=address),
    ])
    t.add_output(TxOutput(out='18CgRLx9hFZqDZv75J5kED7ANnDriwvpi1', satoshi=1700))
    assert t.digest() == expected_digest
