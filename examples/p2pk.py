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
