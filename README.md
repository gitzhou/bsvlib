# bsvlib

[![build](https://github.com/gitzhou/bsvlib/actions/workflows/build.yml/badge.svg)](https://github.com/gitzhou/bsvlib/actions/workflows/build.yml)
[![codecov](https://codecov.io/gh/gitzhou/bsvlib/branch/master/graph/badge.svg?token=ZD1AS8JG9W)](https://codecov.io/gh/gitzhou/bsvlib)
[![PyPI version](https://img.shields.io/pypi/v/bsvlib.svg?style=flat-square)](https://pypi.org/project/bsvlib)
[![Python versions](https://img.shields.io/pypi/pyversions/bsvlib.svg?style=flat-square)](https://pypi.org/project/bsvlib)
[![MIT license](https://img.shields.io/badge/license-MIT-blue.svg?style=flat-square)](https://en.wikipedia.org/wiki/MIT_License)

A Bitcoin SV (BSV) Python Library that is extremely simple to use but more.

- MAINNET and TESTNET supported
- P2PKH and P2PK supported
- All the SIGHASH flags supported
- Additional script types can be customized
- Ability to adapt to different service providers
- Fully ECDSA implementation
- ECDH and Electrum ECIES (aka BIE1) implementation

## Installation

```
$ pip install bsvlib
```

## Examples

1. Send BSV in one line

```python
from bsvlib import Wallet

# Donate to aaron67!
print(Wallet(['YOUR_WIF_GOES_HERE']).send_transaction(outputs=[('1HYeFCE2KG4CW4Jwz5NmDqAZK9Q626ChmN', 724996)]))
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
print(w.send_transaction(outputs=outputs, pushdatas=pushdatas, combine=True))
```

3. Operate P2PK

```python
from bsvlib import Wallet, TxOutput, Transaction
from bsvlib.keys import Key
from bsvlib.script import P2pkScriptType
from bsvlib.service import SensibleQuery

private_key = Key('L5agPjZKceSTkhqZF2dmFptT5LFrbr6ZGPvP7u4A6dvhTrr71WZ9')

w = Wallet(provider=SensibleQuery())
w.add_key(private_key)
w.add_key('5KiANv9EHEU4o9oLzZ6A7z4xJJ3uvfK2RLEubBtTz1fSwAbpJ2U')

t = Transaction()
t.add_inputs(w.get_unspents(refresh=True))
t.add_output(TxOutput(P2pkScriptType.locking(private_key.public_key().serialize()), 996, P2pkScriptType()))
t.add_change(private_key.address())

print(t.sign().broadcast())
```

4. Sign with different SIGHASH flags, [more examples](https://github.com/gitzhou/bsvlib/tree/master/examples)

```python
from bsvlib import Wallet, Transaction, TxInput, TxOutput
from bsvlib.constants import SIGHASH
from bsvlib.keys import Key

private_key = Key('L5agPjZKceSTkhqZF2dmFptT5LFrbr6ZGPvP7u4A6dvhTrr71WZ9')
unspents = Wallet([private_key]).get_unspents(refresh=True)

t = Transaction()
t.add_input(TxInput(unspents[0], sighash=SIGHASH.SINGLE_FORKID))
t.add_output(TxOutput(private_key.address(), 135))
t.sign()

# it's good to append any outputs AFTER the first output, no need to sign, can broadcast directly
print(t.add_change().broadcast())
```

5. Sign arbitrary text with private key

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

6. Encrypt message with public key, decrypt with the corresponding private key

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

## Credits

- [@AustEcon](https://github.com/AustEcon/bitsv)
- [@xiangpengm](https://github.com/xiangpengm)

## Donation

If you like my work or have found this library useful, feel free to donate me a cup of coffee.

Every little satoshi helps. 👏

```
1HYeFCE2KG4CW4Jwz5NmDqAZK9Q626ChmN
```

![](https://aaron67-public.oss-cn-beijing.aliyuncs.com/202201200232249.png?x-oss-process=image/resize,p_50)
