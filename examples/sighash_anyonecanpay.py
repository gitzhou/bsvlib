from bsvlib import Wallet, Transaction, TxInput
from bsvlib.constants import SIGHASH
from bsvlib.keys import Key

private_key = Key('L5agPjZKceSTkhqZF2dmFptT5LFrbr6ZGPvP7u4A6dvhTrr71WZ9')
unspents = Wallet([private_key]).get_unspents(refresh=True)

t = Transaction()
t.add_input(TxInput(unspents[0], sighash=SIGHASH.NONE_ANYONECANPAY_FORKID))
t.sign()

# it's good to add more inputs here
t.add_inputs(unspents[1:])
# function sign will ONLY sign inputs which unlocking script is empty
# because the first input was signed before, so it will NOT be re-signed this time
t.add_change().sign()

print(t.broadcast())
