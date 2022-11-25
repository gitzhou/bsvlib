import pytest

from bsvlib.hd.bip32 import Xpub, Xprv, ckd, master_xprv_from_seed
from bsvlib.hd.bip39 import WordList, mnemonic_from_entropy, seed_from_mnemonic, validate_mnemonic
from bsvlib.hd.bip44 import derive_xprvs_from_mnemonic, derive_xkeys_from_xkey

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

    assert str(master_xprv_from_seed(_seed)) == master_xprv


def test_ckd():
    assert ckd(Xprv(master_xprv), "m") == Xprv(master_xprv)
    assert ckd(Xprv(master_xprv), ".") == Xprv(master_xprv)
    assert ckd(Xprv(master_xprv), "m/0'") == Xprv(hardened_xprv)
    assert ckd(Xprv(master_xprv), "./0'") == Xprv(hardened_xprv)
    assert ckd(Xpub(master_xpub), 'm/0') == Xpub(normal_xpub)
    assert ckd(Xpub(master_xpub), './0') == Xpub(normal_xpub)

    with pytest.raises(AssertionError, match=r'absolute path for non-master key'):
        ckd(Xpub(normal_xpub), 'm/0')

    with pytest.raises(AssertionError, match=r"can't make hardened derivation from xpub"):
        ckd(Xpub(master_xpub), "m/0'")


def test_wordlist():
    assert WordList.get_word(0) == 'abandon'
    assert WordList.get_word(9) == 'abuse'
    assert WordList.get_word(b'\x01\x02') == 'cake'
    assert WordList.get_word(2047) == 'zoo'
    with pytest.raises(AssertionError, match=r'index out of range'):
        WordList.get_word(2048)
    with pytest.raises(AssertionError, match=r'wordlist not supported'):
        WordList.get_word(0, 'zh-tw')

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

    with pytest.raises(AssertionError, match=r'invalid mnemonic, bad entropy bit length'):
        validate_mnemonic('license expire dragon express pulse behave sibling draft vessel')
    with pytest.raises(AssertionError, match=r'invalid mnemonic, checksum mismatch'):
        validate_mnemonic('dignity candy ostrich wide enrich bubble solid sun cannon deposit merge replace')

    path = "m/44'/0'/0'/0/0"
    mnemonic = '塔 恨 非 送 惨 右 娘 适 呵 二 溶 座 伸 徐 鼓'
    seed = 'fb520b58b6db65172fb00322826a902463b0e6af6f2dfd400ce77b528e81f6cbc785835e7e7f7aec5368916b96607f2a1b348bfa483bf8d3a23acf744b4ce209'
    assert seed_from_mnemonic(mnemonic, lang='zh-cn').hex() == seed
    assert ckd(master_xprv_from_seed(seed_from_mnemonic(mnemonic, 'zh-cn')), path).address() == '1C5XJhzRNDDuPNzETmJFFhkU46s1bBFqyV'

    mnemonic = '猛 念 回 风 自 将 大 鸟 说 揭 召 必 旱 济 挡 陆 染 昏'
    seed = '1a9553b9a7d7a394841ca8f5883bf5366c4c7a8ace58b5d32bd291dd9bfa25072253e9904e943ffe426f334bd8275595a87c425f8713b619945155fd5e88a390'
    assert seed_from_mnemonic(mnemonic, lang='zh-cn').hex() == seed
    assert ckd(master_xprv_from_seed(seed_from_mnemonic(mnemonic, 'zh-cn')), path).address() == '1GeiN188BR499mp4JvT1EHD7MVUZ1jJVMj'

    mnemonic = '部 街 缓 弯 醒 巧 传 文 馆 央 怕 纬 疾 沸 静 丘 促 罗 辅 追 勃'
    seed = 'cd552980402550f9ec350cd63cb582d1087c333dbf5044c48ee0ec9f083636193b3738ae04d18198476904fdcd5955764b5f5630b0db0d35d311d0a0fd9b7e8d'
    assert seed_from_mnemonic(mnemonic, lang='zh-cn').hex() == seed
    assert ckd(master_xprv_from_seed(seed_from_mnemonic(mnemonic, 'zh-cn')), path).address() == '1PUaGha3pSPUwCT7JTLTXUdnL9wbvibU1u'


def test_derive():
    mnemonic = 'chief december immune nominee forest scheme slight tornado cupboard post summer program'

    assert [xprv.private_key().wif() for xprv in derive_xprvs_from_mnemonic(mnemonic, 2, 0)] == []

    assert [xprv.private_key().wif() for xprv in derive_xprvs_from_mnemonic(mnemonic, 0, 2)] == [
        'KwW635XeepCG6SzpSMugJ2XDckdnoP6DsDSvg1kjLt11tEJyYaSH',
        'L1QcQMMtXar4nb9hkWdmawumopgKZfRi4Ge1T143w3mBWw7QmuU1',
    ]

    assert [xprv.private_key().wif() for xprv in derive_xprvs_from_mnemonic(mnemonic, "1'", "3'")] == [
        'L3hELjh4wmLgrWEqK2mLsMW3WL3BiYYN3e7wP4s8Xtqi9M8sfNwq',
        'L2orKKStKu1zB2gUzwvEosy8nzohBKBYHZpPThHJ9a6imJs687RA',
    ]

    assert [xprv.private_key().wif() for xprv in derive_xprvs_from_mnemonic(mnemonic, 0, 2, change=1)] == [
        'L4ihevFGHEu3Hdk8TDCucLkyrDSntxhiEnjp2SQARPEnmHXsMG2L',
        'KzRrUofZDgfArmmhqtuS7EMvTUmvWT7BGpqJdCJzmBiwWixatiEk',
    ]

    assert [xprv.private_key().wif() for xprv in derive_xprvs_from_mnemonic(mnemonic, 0, 2, change="0'")] == [
        'L4gRZpDf5Nm6JrowpcX9Z8zmxKNNgiWE61uBb4xF2i8Y9DjXiK5u',
        'KwxW8VrNkoxjjyH22cMPv6ZbBKZKTcV6iSqjTP73daih4fyg3znY',
    ]

    assert [xprv.private_key().wif() for xprv in derive_xprvs_from_mnemonic(mnemonic, 0, 2, path="m/44'/236'/0'")] == [
        'L4toENSefoBpDJcfGAwrSMcyqBNmfSYjgkAP2qeNujw5oPQGvNtM',
        'KzwYj8kMuNqmxLModB1nyPoZjPskCqPXJHf6oUdpHkBK6ZgDUoHE',
    ]

    assert [xprv.private_key().wif() for xprv in derive_xprvs_from_mnemonic(mnemonic, 0, 2, passphrase='bitcoin')] == [
        'L3BWttJh9azQPvvYwFHeEyPniDTCA9TSaPqHKA7jadLVUHDg8KKC',
        'L3h1AvgvscQ1twBTgrH522yNtBfvPjSue3zfH5YRQCt6PdV7FdwS',
    ]

    mnemonic = '安 效 架 碱 皮 伐 鸭 膨 何 泰 陕 森'

    assert [xprv.private_key().wif() for xprv in derive_xprvs_from_mnemonic(mnemonic, 0, 2, lang='zh-cn')] == [
        'KxmA3w8DSR37eD5RqqgkrHHjLgWkZbhyotDd3EehXjvKKziucpwd',
        'L4Q21pxZZpMHWnH19FypFmQhkkxgj1ZSMeCbSfdELu5HnZZm1yJk',
    ]

    xpub = Xpub('xpub6Cz7kFTJ71HQPZpSb8SF2naobZ6HnLgZ8izFEJ31A5R4aR4c3sgHGP8KFwSJbUKLuBeNM4CdXHdrWTqC4sViEHTdv9mXAdCy2E3e6kjUWfB')

    assert [xpub.address() for xpub in derive_xkeys_from_xkey(xpub, 0, 1)] == ['1NDA9czdzkaJFA5Cj1TRyKeews5GrJ9QKR']

    with pytest.raises(AssertionError, match=r"can't make hardened derivation from xpub"):
        derive_xkeys_from_xkey(xpub, "0'", "1'")
