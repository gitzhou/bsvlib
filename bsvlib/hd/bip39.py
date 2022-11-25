import os
from contextlib import suppress
from hashlib import pbkdf2_hmac
from secrets import randbits
from typing import List, Dict, Union

from ..constants import BIP39_ENTROPY_BIT_LENGTH_LIST, BIP39_ENTROPY_BIT_LENGTH
from ..hash import sha256
from ..utils import bytes_to_bits, bits_to_bytes


class WordList:
    """
    BIP39 word list
    """
    LIST_WORDS_COUNT: int = 2048

    path = os.path.join(os.path.dirname(__file__), 'wordlist')
    #
    # en
    #   https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt
    # zh-cn
    #   https://github.com/bitcoin/bips/blob/master/bip-0039/chinese_simplified.txt
    #
    files: Dict[str, str] = {
        'en': os.path.join(path, 'english.txt'),
        'zh-cn': os.path.join(path, 'chinese_simplified.txt'),
    }
    wordlist: Dict[str, List[str]] = {}

    @classmethod
    def load(cls) -> None:
        for lang in WordList.files.keys():
            if not WordList.wordlist.get(lang):
                WordList.wordlist[lang] = WordList.load_wordlist(lang)

    @classmethod
    def load_wordlist(cls, lang: str = 'en') -> List[str]:
        assert lang in WordList.files.keys(), f'{lang} wordlist not supported'
        with open(WordList.files[lang], 'r', encoding='utf-8') as f:
            words: List[str] = f.read().splitlines()
        assert len(words) == WordList.LIST_WORDS_COUNT, 'broken wordlist file'
        return words

    @classmethod
    def get_word(cls, index: Union[int, bytes], lang: str = 'en') -> str:
        WordList.load()
        assert lang in WordList.wordlist.keys(), f'{lang} wordlist not supported'
        if isinstance(index, bytes):
            index = int.from_bytes(index, 'big')
        assert 0 <= index < WordList.LIST_WORDS_COUNT, 'index out of range'
        return WordList.wordlist[lang][index]

    @classmethod
    def index_word(cls, word: str, lang: str = 'en') -> int:
        WordList.load()
        assert lang in WordList.wordlist.keys(), f'{lang} wordlist not supported'
        with suppress(Exception):
            return WordList.wordlist[lang].index(word)
        raise ValueError('invalid word')


def mnemonic_from_entropy(entropy: Union[bytes, str, None] = None, lang: str = 'en') -> str:
    if entropy:
        assert type(entropy).__name__ in ['bytes', 'str'], 'unsupported entropy type'
        entropy_bytes = entropy if isinstance(entropy, bytes) else bytes.fromhex(entropy)
    else:
        # random a new entropy
        entropy_bytes = randbits(BIP39_ENTROPY_BIT_LENGTH).to_bytes(BIP39_ENTROPY_BIT_LENGTH // 8, 'big')
    entropy_bits: str = bytes_to_bits(entropy_bytes)
    assert len(entropy_bits) in BIP39_ENTROPY_BIT_LENGTH_LIST, 'invalid entropy bit length'
    checksum_bits: str = bytes_to_bits(sha256(entropy_bytes))[:len(entropy_bits) // 32]

    bits: str = entropy_bits + checksum_bits
    indexes_bits: List[str] = [bits[i:i + 11] for i in range(0, len(bits), 11)]
    return ' '.join([WordList.get_word(bits_to_bytes(index_bits), lang) for index_bits in indexes_bits])


def validate_mnemonic(mnemonic: str, lang: str = 'en'):
    indexes: List[int] = [WordList.index_word(word, lang) for word in mnemonic.split(' ')]
    bits: str = ''.join([bin(index)[2:].zfill(11) for index in indexes])
    entropy_bit_length: int = len(bits) * 32 // 33
    assert entropy_bit_length in BIP39_ENTROPY_BIT_LENGTH_LIST, 'invalid mnemonic, bad entropy bit length'
    entropy_bits: str = bits[:entropy_bit_length]
    checksum_bits: str = bytes_to_bits(sha256(bits_to_bytes(entropy_bits)))[:entropy_bit_length // 32]
    assert checksum_bits == bits[entropy_bit_length:], 'invalid mnemonic, checksum mismatch'


def seed_from_mnemonic(mnemonic: str, lang: str = 'en', passphrase: str = '', prefix: str = 'mnemonic') -> bytes:
    validate_mnemonic(mnemonic, lang)
    hash_name = 'sha512'
    password = mnemonic.encode()
    salt = (prefix + passphrase).encode()
    iterations = 2048
    dklen = 64
    return pbkdf2_hmac(hash_name, password, salt, iterations, dklen)
