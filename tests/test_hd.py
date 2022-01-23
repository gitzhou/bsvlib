import pytest

from bsvlib.hd.bip32 import Xpub, Xprv, derive
from bsvlib.hd.bip39 import WordList, mnemonic_from_entropy, seed_from_mnemonic

_mnemonic = 'slice simple ring fluid capital exhaust will illegal march annual shift hood'
_seed = '4fc3bea5ae2df6c5a93602e87085de5a7c1e94bb7ab5e6122364753cc51aa5e210c32aec1c58ed570c83084ec3b60b4ad69075bc62c05edb8e538ae2843f4f59'

master_xprv = 'xprv9s21ZrQH143K4SSfHuCgyJKsown12SFNpzCf3XYJT67mkaVaWCCBqiGBRZRmgk2ypzXoWzAccyVPGBW69A6LLRMnbY6GZ27q6UkiJDnPjhT'
master_xpub = 'xpub661MyMwAqRbcGvX8PvjhLSGcMycVRtyECD8Fquwv1RekdNpj3jWSPWafGsdNa6TNVmDN9HpPe2tRPofzHTYAUeQFUsAQpzuVSDDyUCt975T'

# m/0
normal_xprv = 'xprv9v35D6cvdU6R1d3UuY6bbR87h6pJLQn3kXY9jwGXhqTX129XT5jZnEyTDoDKnoE9k7HSK7MNv7E3gEGkt4Bp7BkcgHgXUHzQHXueD1t2vRj'
normal_xpub = 'xpub692Rcc9pTqeiE77x1ZdbxZ4rF8enjsVu7kTkYKg9GAzVspUfzd3pL3Hw56Fkgg4vrhayKd6k33uiJgmicfiKf2T1E5brXQLeQni1ake7uSv'

# m/0'
hardened_xprv = 'xprv9v35D6d4y8dP9r1N2koQ49hwzk8EDT4msMFAXGertWPxQDByPqZ1e3k6U34kwU4iCnur3UcxX4SvaDFcrubYd3ktsfpCraGmWpqDq4fm1SJ'
hardened_xpub = 'xpub692Rcc9xoWBgNL5q8nLQRHegYmxicundEaAmKf4USqvwH1X7wNsGBr4aKHLeKDA5ghqECjBErUwLaYZ6As5PpqsFJbZD3jyBWrk6QKG8QQX'


def test_xkey():
    with pytest.raises(TypeError, match=r'unsupported extended key type'):
        # noinspection PyTypeChecker
        Xpub(1)

    assert Xpub.from_xprv(master_xprv) == Xpub(master_xpub)
    assert Xpub.from_xprv(normal_xprv) == Xpub(normal_xpub)
    assert Xpub.from_xprv(Xprv(hardened_xprv)) == Xpub(hardened_xpub)

    assert Xpub(master_xpub).chain_code == Xprv(master_xprv).chain_code

    assert str(Xprv(master_xprv)) == master_xprv
    assert str(Xpub(master_xpub)) == master_xpub

    assert str(Xprv(master_xprv).ckd(0)) == normal_xprv
    assert str(Xprv(master_xprv).ckd('80000000')) == hardened_xprv
    assert str(Xprv(master_xprv).ckd(b'\x80\x00\x00\x00')) == hardened_xprv

    assert str(Xpub(master_xpub).ckd(0)) == normal_xpub
    assert str(Xpub(master_xpub).ckd('00000000')) == normal_xpub
    assert str(Xpub(master_xpub).ckd(b'\x00\x00\x00\x00')) == normal_xpub

    assert str(Xprv(master_xprv).child('0')) == normal_xprv
    assert str(Xprv(master_xprv).child("0'")) == hardened_xprv
    assert str(Xpub(master_xpub).child('0')) == normal_xpub
    with pytest.raises(AssertionError, match=r"can't make hardened derivation from xpub"):
        Xpub(master_xpub).child("0'")

    wif = 'KxegHzrskmyDrSuymrQVEWbLjQRm5y7c9XJYoVFAtfi1uszycQX7'
    public_key_hex = '033394416f0d04d0758e002f6708dd121a4c02eae4fee8734fc359c27bd22a92bd'
    address = '1LRax3BdP3SaSnGoD2pkAMTrbuATtog7Kj'
    assert Xprv(normal_xprv).xpub() == Xpub(normal_xpub)
    assert Xprv(normal_xprv).public_key().hex() == public_key_hex
    assert Xprv(normal_xprv).address() == address
    assert Xprv(normal_xprv).private_key().wif() == wif
    assert Xpub(normal_xpub).public_key().hex() == public_key_hex
    assert Xpub(normal_xpub).address() == address

    assert Xprv.from_seed(_seed) == Xprv(master_xprv)
    assert Xprv.from_seed(bytes.fromhex(_seed)) == Xprv(master_xprv)


def test_derive():
    assert derive(Xprv(master_xprv), "m") == Xprv(master_xprv)
    assert derive(Xprv(master_xprv), ".") == Xprv(master_xprv)
    assert derive(Xprv(master_xprv), "m/0'") == Xprv(hardened_xprv)
    assert derive(Xprv(master_xprv), "./0'") == Xprv(hardened_xprv)
    assert derive(Xpub(master_xpub), 'm/0') == Xpub(normal_xpub)
    assert derive(Xpub(master_xpub), './0') == Xpub(normal_xpub)

    with pytest.raises(AssertionError, match=r'absolute path for non-master key'):
        derive(Xpub(normal_xpub), 'm/0')


def test_wordlist():
    assert WordList.get_word(0) == 'abandon'
    assert WordList.get_word(9) == 'abuse'
    assert WordList.get_word(b'\x01\x02') == 'cake'
    assert WordList.get_word(2047) == 'zoo'
    with pytest.raises(AssertionError, match=r'index out of range'):
        WordList.get_word(2048)
    with pytest.raises(AssertionError, match=r'wordlist not supported'):
        WordList.get_word(0, 'zh-cn')

    assert WordList.index_word('abandon') == 0
    assert WordList.index_word('zoo') == 2047
    with pytest.raises(ValueError, match=r'invalid word'):
        WordList.index_word('hi')


def test_mnemonic():
    assert seed_from_mnemonic(_mnemonic).hex() == _seed

    assert len(mnemonic_from_entropy().split(' ')) == 12

    entropy = '27c715c6caf5b38172ef2b35d51764d5'
    mnemonic = 'chief december immune nominee forest scheme slight tornado cupboard post summer program'
    seed = 'ccf9ff0d7541429ccff7c3c5a03bedd8e736542346f2e020c2151df5169bd14482c761e2cafc9e25990c584867e8b2f2d84ade643109da5e60f1bf03a63c41a7'
    assert mnemonic_from_entropy(entropy) == mnemonic
    assert mnemonic_from_entropy(bytes.fromhex(entropy)) == mnemonic
    assert seed_from_mnemonic(mnemonic).hex() == seed

    entropy = '13b8924d0e0436a6d12200bee8a599c38e31c17ea96a7b58d41b5d3a1aed2339'
    mnemonic = 'beauty setup nation bright drop fat duty divorce same early grid mandate toast thing wide coil kitten shop almost risk payment isolate mind dinner'
    seed = '0c15a3c37a38157147b03225478cdb244b4de24c8da7bd0ccf75893223454caacebae97b5e1d3e966f9a9ce1526944b2b7ca17e21651a0e6f101b01f951008e2'
    assert mnemonic_from_entropy(entropy) == mnemonic
    assert seed_from_mnemonic(mnemonic).hex() == seed

    mnemonic = 'furnace tunnel buyer merry feature stamp brown client fine stomach company blossom'
    seed_default = '2588c36c5d2685b89e5ab06406cd5e96efcc3dc101c4ebd391fc93367e5525aca6c7a5fe4ea8b973c58279be362dbee9a84771707fc6521c374eb10af1044283'
    seed_passphrase = '1e8340ad778a2bbb1ccac4dd02e6985c888a0db0c40d9817998c0ef3da36e846b270f2c51ad67ac6f51183f567fd97c58a31d363296d5dc6245a0a3c4a3e83c5'
    assert seed_from_mnemonic(mnemonic).hex() == seed_default
    assert seed_from_mnemonic(mnemonic, passphrase='bitcoin').hex() == seed_passphrase
