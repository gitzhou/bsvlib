import pytest

from bsvlib.hd.bip32 import Xpub, Xprv, derive

# slice simple ring fluid capital exhaust will illegal march annual shift hood
seed = '4fc3bea5ae2df6c5a93602e87085de5a7c1e94bb7ab5e6122364753cc51aa5e210c32aec1c58ed570c83084ec3b60b4ad69075bc62c05edb8e538ae2843f4f59'

master_xprv = 'xprv9s21ZrQH143K4SSfHuCgyJKsown12SFNpzCf3XYJT67mkaVaWCCBqiGBRZRmgk2ypzXoWzAccyVPGBW69A6LLRMnbY6GZ27q6UkiJDnPjhT'
master_xpub = 'xpub661MyMwAqRbcGvX8PvjhLSGcMycVRtyECD8Fquwv1RekdNpj3jWSPWafGsdNa6TNVmDN9HpPe2tRPofzHTYAUeQFUsAQpzuVSDDyUCt975T'

# m/0
normal_xprv = 'xprv9v35D6cvdU6R1d3UuY6bbR87h6pJLQn3kXY9jwGXhqTX129XT5jZnEyTDoDKnoE9k7HSK7MNv7E3gEGkt4Bp7BkcgHgXUHzQHXueD1t2vRj'
normal_xpub = 'xpub692Rcc9pTqeiE77x1ZdbxZ4rF8enjsVu7kTkYKg9GAzVspUfzd3pL3Hw56Fkgg4vrhayKd6k33uiJgmicfiKf2T1E5brXQLeQni1ake7uSv'

# m/0'
hardened_xprv = 'xprv9v35D6d4y8dP9r1N2koQ49hwzk8EDT4msMFAXGertWPxQDByPqZ1e3k6U34kwU4iCnur3UcxX4SvaDFcrubYd3ktsfpCraGmWpqDq4fm1SJ'
hardened_xpub = 'xpub692Rcc9xoWBgNL5q8nLQRHegYmxicundEaAmKf4USqvwH1X7wNsGBr4aKHLeKDA5ghqECjBErUwLaYZ6As5PpqsFJbZD3jyBWrk6QKG8QQX'


def test_bip32():
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

    assert Xprv.from_seed(seed) == Xprv(master_xprv)
    assert Xprv.from_seed(bytes.fromhex(seed)) == Xprv(master_xprv)


def test_derive():
    assert derive(Xprv(master_xprv), "m") == Xprv(master_xprv)
    assert derive(Xprv(master_xprv), ".") == Xprv(master_xprv)
    assert derive(Xprv(master_xprv), "m/0'") == Xprv(hardened_xprv)
    assert derive(Xprv(master_xprv), "./0'") == Xprv(hardened_xprv)
    assert derive(Xpub(master_xpub), 'm/0') == Xpub(normal_xpub)
    assert derive(Xpub(master_xpub), './0') == Xpub(normal_xpub)

    with pytest.raises(AssertionError, match=r'absolute path for non-master key'):
        derive(Xpub(normal_xpub), 'm/0')
