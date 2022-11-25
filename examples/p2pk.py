import time

from bsvlib import Wallet, TxOutput, Transaction
from bsvlib.constants import Chain
from bsvlib.keys import Key
from bsvlib.script import P2pkScriptType

chain = Chain.TEST
k = Key('cVwfreZB3i8iv9JpdSStd9PWhZZGGJCFLS4rEKWfbkahibwhticA')
unspents = Wallet(chain=chain).add_keys([k, '93UnxexmsTYCmDJdctz4zacuwxQd5prDmH6rfpEyKkQViAVA3me']).get_unspents(refresh=True)

t = Transaction(chain=chain).add_inputs(unspents)
t.add_output(TxOutput(P2pkScriptType.locking(k.public_key().serialize()), 996, P2pkScriptType()))
t.add_change(k.address()).sign()
print(t.broadcast())

time.sleep(2)
tt = Transaction(chain=chain).add_inputs(t.to_unspents(args=[{'private_keys': [k]}] * 2)).add_change(k.address()).sign()
print(tt.broadcast())
