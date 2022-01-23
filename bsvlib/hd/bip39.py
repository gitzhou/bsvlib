import os
from contextlib import suppress
from hashlib import pbkdf2_hmac
from secrets import randbits
from typing import List, Dict, Union

from ..hash import sha256
from ..utils import bytes_to_bits, bits_to_bytes


class WordList:
    """
    BIP39 word list
    """
    WORD_COUNT: int = 2048

    path = os.path.join(os.path.dirname(__file__), 'wordlist')
    #
    # en - english - https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt
    #
    files: Dict[str, str] = {
        'en': os.path.join(path, 'english.txt'),
    }
    words: Dict[str, List[str]] = {}

    @classmethod
    def load(cls) -> None:
        for lang in WordList.files.keys():
            if not WordList.words.get(lang):
                WordList.words[lang] = WordList.load_wordlist(lang)

    @classmethod
    def load_wordlist(cls, lang: str = 'en') -> List[str]:
        assert lang in WordList.files.keys(), f'{lang} wordlist not supported'
        with open(WordList.files[lang], 'r') as f:
            words: List[str] = f.read().splitlines()
        assert len(words) == WordList.WORD_COUNT, 'broken wordlist file'
        return words

    @classmethod
    def get_word(cls, index: Union[int, bytes], lang: str = 'en') -> str:
        WordList.load()
        assert lang in WordList.words.keys(), f'{lang} wordlist not supported'
        if isinstance(index, bytes):
            index = int.from_bytes(index, 'big')
        assert 0 <= index < WordList.WORD_COUNT, 'index out of range'
        return WordList.words[lang][index]

    @classmethod
    def index_word(cls, word: str, lang: str = 'en') -> int:
        WordList.load()
        assert lang in WordList.words.keys(), f'{lang} wordlist not supported'
        with suppress(Exception):
            return WordList.words[lang].index(word)
        raise ValueError('invalid word')


ENTROPY_BIT_LENGTH_LIST: List[int] = [128, 160, 192, 224, 256]
DEFAULT_ENTROPY_BIT_LENGTH: int = 128


def mnemonic_from_entropy(entropy: Union[bytes, str, None] = None, lang: str = 'en') -> str:
    if entropy:
        assert type(entropy).__name__ in ['bytes', 'str'], 'unsupported entropy type'
        entropy_bytes = entropy if isinstance(entropy, bytes) else bytes.fromhex(entropy)
    else:
        # random a new 128 bits entropy --> 12 words mnemonic
        entropy_bytes = randbits(DEFAULT_ENTROPY_BIT_LENGTH).to_bytes(DEFAULT_ENTROPY_BIT_LENGTH // 8, 'big')
    entropy_bits: str = bytes_to_bits(entropy_bytes)
    assert len(entropy_bits) in ENTROPY_BIT_LENGTH_LIST, 'invalid entropy bit length'
    checksum_bits: str = bytes_to_bits(sha256(entropy_bytes))[:len(entropy_bits) // 32]

    bits: str = entropy_bits + checksum_bits
    indexes_bits: List[str] = [bits[i:i + 11] for i in range(0, len(bits), 11)]
    return ' '.join([WordList.get_word(bits_to_bytes(index_bits), lang) for index_bits in indexes_bits])


def seed_from_mnemonic(mnemonic: str, passphrase: str = '', prefix: str = 'mnemonic') -> bytes:
    hash_name = 'sha512'
    password = mnemonic.encode()
    salt = (prefix + passphrase).encode()
    iterations = 2048
    dklen = 64
    return pbkdf2_hmac(hash_name, password, salt, iterations, dklen)
