from bsvlib import Wallet, Transaction, TxInput, TxOutput
from bsvlib.constants import SIGHASH
from bsvlib.keys import Key
from bsvlib.service import WhatsOnChain

provider = WhatsOnChain()
private_key = Key('L5agPjZKceSTkhqZF2dmFptT5LFrbr6ZGPvP7u4A6dvhTrr71WZ9')
unspents = Wallet([private_key]).get_unspents(refresh=True, provider=provider)

t = Transaction(provider=provider)
t.add_input(TxInput(unspents[0], sighash=SIGHASH.SINGLE_FORKID))
t.add_output(TxOutput(private_key.address(), 135))
t.sign()

# it's good to append any outputs AFTER the first output, no need to sign, can broadcast directly
print(t.add_change().broadcast())
