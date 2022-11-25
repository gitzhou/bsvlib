from typing import List

from bsvlib.hd import mnemonic_from_entropy, seed_from_mnemonic, master_xprv_from_seed, Xprv, derive_xprvs_from_mnemonic

#
# HD derivation
#
entropy = 'cd9b819d9c62f0027116c1849e7d497f'

# snow swing guess decide congress abuse session subway loyal view false zebra
mnemonic: str = mnemonic_from_entropy(entropy)
print(mnemonic)

seed: bytes = seed_from_mnemonic(mnemonic)
print(seed.hex())

master_xprv: Xprv = master_xprv_from_seed(seed)
print(master_xprv)

print()
keys: List[Xprv] = derive_xprvs_from_mnemonic(mnemonic, path="m/44'/0'/0'", change=1, index_start=0, index_end=5)
for key in keys:
    print(key.address(), key.private_key().wif())

#
# random mnemonic
#
print()
print(mnemonic_from_entropy())
print(mnemonic_from_entropy(lang='en'))
print(mnemonic_from_entropy(lang='zh-cn'))
