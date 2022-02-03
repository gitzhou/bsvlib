from bsvlib import Key, Wallet, Transaction, TxInput, TxOutput
from bsvlib.constants import SIGHASH, Chain
from bsvlib.service import WhatsOnChain

provider = WhatsOnChain(Chain.TEST)
private_key = Key('cVwfreZB3i8iv9JpdSStd9PWhZZGGJCFLS4rEKWfbkahibwhticA')
unspents = Wallet([private_key]).get_unspents(refresh=True, provider=provider)

t = Transaction(provider=provider)
t.add_input(TxInput(unspents[0], sighash=SIGHASH.SINGLE_FORKID))
t.add_output(TxOutput(private_key.address(), 135))
t.sign()

# it's good to append any outputs AFTER the first output, no need to sign, can broadcast directly
print(t.add_change().broadcast())
