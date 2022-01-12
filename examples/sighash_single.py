from bsvlib import Wallet, Transaction, TxInput, TxOutput
from bsvlib.constants import SIGHASH

unspents = Wallet(['L5agPjZKceSTkhqZF2dmFptT5LFrbr6ZGPvP7u4A6dvhTrr71WZ9']).get_unspents(refresh=True)

t = Transaction()
t.add_input(TxInput(unspents[0], sighash=SIGHASH.SINGLE_FORKID))
t.add_output(TxOutput('1AfxgwYJrBgriZDLryfyKuSdBsi59jeBX9', 135))
t.sign()

# it's good to append any outputs AFTER the first output, no need to sign, can broadcast directly
print(t.add_change('1BVHzn1J8VZWRuVWbPrj2Szx1j7hHdt5zP').broadcast())
