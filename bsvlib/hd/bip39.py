import os
from contextlib import suppress
from typing import List, Dict, Union


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
