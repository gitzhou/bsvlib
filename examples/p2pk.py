from bsvlib import Wallet, TxOutput, Transaction
from bsvlib.keys import PrivateKey
from bsvlib.script import P2pkScriptType
from bsvlib.service import SensibleQuery

private_key = PrivateKey('L5agPjZKceSTkhqZF2dmFptT5LFrbr6ZGPvP7u4A6dvhTrr71WZ9')
w = Wallet(provider=SensibleQuery()).add_key(private_key)

t = Transaction()
t.add_inputs(w.get_unspents(refresh=True))
t.add_output(TxOutput(P2pkScriptType.locking(private_key.public_key().serialize()), 996, P2pkScriptType()))
t.add_change().sign()

print(t.broadcast())
