from bsvlib import Wallet, TxOutput, Transaction
from bsvlib.constants import Chain
from bsvlib.keys import Key
from bsvlib.script import P2pkScriptType
from bsvlib.service import SensibleQuery

k = Key('cVwfreZB3i8iv9JpdSStd9PWhZZGGJCFLS4rEKWfbkahibwhticA')
p = SensibleQuery(chain=Chain.TEST)
unspents = Wallet(provider=p).add_keys([k, '93UnxexmsTYCmDJdctz4zacuwxQd5prDmH6rfpEyKkQViAVA3me']).get_unspents(refresh=True)

t = Transaction(provider=p)
t.add_inputs(unspents)
t.add_output(TxOutput(P2pkScriptType.locking(k.public_key().serialize()), 996, P2pkScriptType()))
t.add_change(k.address())

print(t.sign().broadcast())
