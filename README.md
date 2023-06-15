# bsvlib

[![build](https://github.com/gitzhou/bsvlib/actions/workflows/build.yml/badge.svg)](https://github.com/gitzhou/bsvlib/actions/workflows/build.yml)
[![codecov](https://codecov.io/gh/gitzhou/bsvlib/branch/master/graph/badge.svg?token=ZD1AS8JG9W)](https://codecov.io/gh/gitzhou/bsvlib)
[![PyPI version](https://img.shields.io/pypi/v/bsvlib)](https://pypi.org/project/bsvlib)
[![Python versions](https://img.shields.io/pypi/pyversions/bsvlib)](https://pypi.org/project/bsvlib)
[![MIT license](https://img.shields.io/badge/license-MIT-blue)](https://en.wikipedia.org/wiki/MIT_License)

A Bitcoin SV (BSV) Python Library that is extremely simple to use but more.

- MAINNET and TESTNET supported
- P2PKH, P2PK, and bare-multisig supported
- All the SIGHASH flags supported
- Additional script types can be customized
- [MetaSV](https://metasv.com/) and [WhatsOnChain](https://developers.whatsonchain.com/) API integrated
- Ability to adapt to different service providers
- Fully ECDSA implementation
- ECDH and Electrum ECIES (aka BIE1) implementation
- HD implementation (BIP-32, BIP-39, BIP-44)

## Installation

```
$ pip install bsvlib
```

## Examples

1. Send BSV in one line

```python
from bsvlib import Wallet

# Donate to aaron67!
outputs = [('1HYeFCE2KG4CW4Jwz5NmDqAZK9Q626ChmN', 724996)]
print(Wallet(['YOUR_WIF']).create_transaction(outputs=outputs).broadcast())
```

2. Send unspent locked by different keys in one transaction, support OP_RETURN output as well

```python
from bsvlib import Wallet
from bsvlib.constants import Chain

w = Wallet(chain=Chain.TEST)

w.add_key('cVwfreZB3i8iv9JpdSStd9PWhZZGGJCFLS4rEKWfbkahibwhticA')
w.add_key('93UnxexmsTYCmDJdctz4zacuwxQd5prDmH6rfpEyKkQViAVA3me')
print(w.get_balance(refresh=True))

outputs = [('mqBuyzdHfD87VfgxaYeM9pex3sJn4ihYHY', 724), ('mr1FHq6GwWzmD1y8Jxq6rNDGsiiQ9caF7r', 996)]
pushdatas = ['hello', b'world']
print(w.create_transaction(outputs=outputs, pushdatas=pushdatas, combine=True).broadcast())
```

3. Operate P2PK

```python
import time

from bsvlib import Wallet, TxOutput, Transaction
from bsvlib.constants import Chain
from bsvlib.keys import Key
from bsvlib.script import P2pkScriptType

chain = Chain.TEST

k = Key('cVwfreZB3i8iv9JpdSStd9PWhZZGGJCFLS4rEKWfbkahibwhticA')
p2pk_output = TxOutput(P2pkScriptType.locking(k.public_key().serialize()), 996, P2pkScriptType())

unspents = Wallet(chain=chain).add_keys([k, '93UnxexmsTYCmDJdctz4zacuwxQd5prDmH6rfpEyKkQViAVA3me']).get_unspents(refresh=True)
t = Transaction(chain=chain).add_inputs(unspents).add_output(p2pk_output).add_change(k.address()).sign()
print('create p2pk:', t.broadcast())

time.sleep(2)
unspents = t.to_unspents(args=[{'private_keys': [k]}] * 2)
t = Transaction(chain=chain).add_inputs(unspents).add_change(k.address()).sign()
print('sepnd p2pk:', t.broadcast())
```

4. Operate bare-multisig

```python
import time
from typing import List, Union

from bsvlib import Key, Unspent, Transaction, TxOutput
from bsvlib.constants import Chain
from bsvlib.script import BareMultisigScriptType, Script
from bsvlib.service import WhatsOnChain

k1 = Key('cVwfreZB3i8iv9JpdSStd9PWhZZGGJCFLS4rEKWfbkahibwhticA')
k2 = Key('93UnxexmsTYCmDJdctz4zacuwxQd5prDmH6rfpEyKkQViAVA3me')
provider = WhatsOnChain(Chain.TEST)
unspents = Unspent.get_unspents(provider=provider, private_keys=[k1])

# a 2-of-3 multi-sig output
public_keys: List[Union[str, bytes]] = [k1.public_key().hex(), Key().public_key().hex(), k2.public_key().serialize()]
multisig_script: Script = BareMultisigScriptType.locking(public_keys, 2)
output = TxOutput(out=multisig_script, satoshi=1000, script_type=BareMultisigScriptType())

# create a multi-sig output
t = Transaction(provider=provider).add_inputs(unspents).add_output(output).add_change().sign()
r = t.broadcast()
print(f'create multisig - {r}')
assert r.propagated
time.sleep(2)

# send the multi-sig unspent we just created
unspent = t.to_unspent(0, private_keys=[k1, k2])
r = Transaction(provider=provider).add_input(unspent).add_change(k1.address()).sign().broadcast()
print(f'spend multisig - {r}')
```

5. Sign with different SIGHASH flags, [more examples](https://github.com/gitzhou/bsvlib/tree/master/examples)

```python
from bsvlib import Key, Wallet, Transaction, TxInput, TxOutput
from bsvlib.constants import SIGHASH, Chain
from bsvlib.service import WhatsOnChain

provider = WhatsOnChain(Chain.TEST)
private_key = Key('cVwfreZB3i8iv9JpdSStd9PWhZZGGJCFLS4rEKWfbkahibwhticA')
unspents = Wallet([private_key]).get_unspents(refresh=True, provider=provider)

t = Transaction(provider=provider)
t.add_input(TxInput(unspents[0], sighash=SIGHASH.SINGLE_FORKID))
t.add_output(TxOutput(private_key.address(), 135))
t.sign()

# it's good to append any outputs AFTER the first output, no need to sign, can broadcast directly
print(t.add_change().broadcast())
```

6. Sign arbitrary text with private key

```python
from bsvlib import Key, verify_signed_text

private_key = Key('L5agPjZKceSTkhqZF2dmFptT5LFrbr6ZGPvP7u4A6dvhTrr71WZ9')
text = 'hello world'

# sign arbitrary text with bitcoin private key
address, signature = private_key.sign_text(text)

# verify https://reinproject.org/bitcoin-signature-tool/
print(address, signature)

# verify
print(verify_signed_text(text, address, signature))
```

7. Encrypt message with public key, decrypt with the corresponding private key

```python
from bsvlib import Key

private_key = Key('L5agPjZKceSTkhqZF2dmFptT5LFrbr6ZGPvP7u4A6dvhTrr71WZ9')
public_key = private_key.public_key()

plain = 'hello world'

# use public key to encrypt
encrypted = public_key.encrypt_text(plain)
print(encrypted)

# decrypt with the corresponding private key
print(private_key.decrypt_text(encrypted))
```

8. Process HD wallet derivation

![image](https://user-images.githubusercontent.com/1585505/150875831-2663e158-b00d-4089-8276-1ad72e335d28.png)

```python
from typing import List

from bsvlib.hd import mnemonic_from_entropy, Xprv, derive_xprvs_from_mnemonic

#
# HD derivation
#
entropy = 'cd9b819d9c62f0027116c1849e7d497f'

# snow swing guess decide congress abuse session subway loyal view false zebra
mnemonic: str = mnemonic_from_entropy(entropy)
print(mnemonic)

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
```

## Credits

- [AustEcon / bitsv](https://github.com/AustEcon/bitsv)
- [ofek / coincurve](https://github.com/ofek/coincurve/)
- [btclib-org / btclib](https://github.com/btclib-org/btclib)
- [@xiangpengm](https://github.com/xiangpengm)

## Donation

If you like my work or have found this library useful, feel free to donate me a cup of coffee.

Every little satoshi helps. 👏

```
1HYeFCE2KG4CW4Jwz5NmDqAZK9Q626ChmN
```

![](https://aaron67-public.oss-cn-beijing.aliyuncs.com/202201200232249.png?x-oss-process=image/resize,p_50)
