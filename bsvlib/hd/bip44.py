from typing import Union, List

from .bip32 import Xprv, Xpub, step_to_index, ckd
from .bip39 import seed_from_mnemonic
from ..constants import Chain


def derive_from_xkey(xkey: Union[Xprv, Xpub], index_start: Union[str, int], index_end: Union[str, int],
                     change: Union[str, int] = 0) -> List[Union[Xprv, Xpub]]:
    """
    derive extended keys according to path "./change/index"
    """
    change_xkey = xkey.ckd(step_to_index(change))
    return [change_xkey.ckd(i) for i in range(step_to_index(index_start), step_to_index(index_end))]


def derive_from_mnemonic(mnemonic: str, index_start: Union[str, int], index_end: Union[str, int],
                         lang: str = 'en', passphrase: str = '', prefix: str = 'mnemonic',
                         path: str = "m/44'/0'/0'", change: Union[str, int] = 0, chain: Chain = Chain.MAIN) -> List[Xprv]:
    seed = seed_from_mnemonic(mnemonic, lang, passphrase, prefix)
    master_xprv = Xprv.from_seed(seed, chain)
    xprv = ckd(master_xprv, path)
    return derive_from_xkey(xprv, index_start, index_end, change)
