from bsvlib import Wallet, Transaction, TxInput, TxOutput
from bsvlib.constants import SIGHASH
from bsvlib.service import SensibleQuery

t = Transaction(provider=SensibleQuery())

alice_unspents = Wallet(['L5agPjZKceSTkhqZF2dmFptT5LFrbr6ZGPvP7u4A6dvhTrr71WZ9']).get_unspents(refresh=True)
t.add_input(TxInput(alice_unspents[0], sighash=SIGHASH.SINGLE_ANYONECANPAY_FORKID))
t.add_output(TxOutput('1AfxgwYJrBgriZDLryfyKuSdBsi59jeBX9', 500))
# function sign will ONLY sign inputs without unlocking script by default
# set no_bypass to sign all the inputs even if their unlocking script is ready
t.sign()

bob_unspents = Wallet(['5KiANv9EHEU4o9oLzZ6A7z4xJJ3uvfK2RLEubBtTz1fSwAbpJ2U']).get_unspents(refresh=True)
t.add_inputs(bob_unspents)
t.add_change('1BVHzn1J8VZWRuVWbPrj2Szx1j7hHdt5zP')
# because unspent of alice is ready, so it will NOT be re-signed here
# means only unspent of bob will be signed this time
t.sign()

print(t.broadcast())
