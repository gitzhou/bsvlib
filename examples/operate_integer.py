import random

from bsvlib import Key, Transaction, Unspent, TxOutput, TxInput
from bsvlib.constants import Chain, OP
from bsvlib.script import Script
from bsvlib.service import WhatsOnChain
from bsvlib.utils import encode_int

provider = WhatsOnChain(Chain.TEST)
k = Key('cVwfreZB3i8iv9JpdSStd9PWhZZGGJCFLS4rEKWfbkahibwhticA')

a = random.randint(-128, 128)
b = random.randint(-128, 128)
print(a, b)

t = Transaction(provider=provider)
t.add_inputs(Unspent.get_unspents(provider=provider, private_keys=[k]))
# locking script requires the result of a + b
script = Script(encode_int(a) + encode_int(b) + OP.OP_ADD + OP.OP_EQUAL)
txid = t.add_output(TxOutput(script, 1000)).add_change().sign().broadcast()
print(f'create - {txid}')

unspent = Unspent(txid=txid, vout=0, satoshi=1000, locking_script=script)
t = Transaction(provider=provider)
t.add_input(TxInput(unspent, unlocking_script=Script(encode_int(a + b))))
txid = t.add_output(TxOutput(k.address(), 800)).broadcast()
print(f'spend - {txid}')
