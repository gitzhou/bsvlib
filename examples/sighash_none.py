from bsvlib import Wallet, Transaction, TxInput
from bsvlib.constants import SIGHASH

unspents = Wallet(['L5agPjZKceSTkhqZF2dmFptT5LFrbr6ZGPvP7u4A6dvhTrr71WZ9']).get_unspents(refresh=True)

t = Transaction()
t.add_inputs([TxInput(unspent, sighash=SIGHASH.NONE_FORKID) for unspent in unspents])
t.sign()

# it's good to add any outputs here, no need to sign, can broadcast directly
print(t.add_change('1AfxgwYJrBgriZDLryfyKuSdBsi59jeBX9').broadcast())
