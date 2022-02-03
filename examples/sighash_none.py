from bsvlib import Unspent, Transaction, TxInput, Key
from bsvlib.constants import SIGHASH, Chain
from bsvlib.service import WhatsOnChain

provider = WhatsOnChain(Chain.TEST)
private_key = Key('cVwfreZB3i8iv9JpdSStd9PWhZZGGJCFLS4rEKWfbkahibwhticA')
unspents = Unspent.get_unspents(provider=provider, private_keys=[private_key])

t = Transaction(provider=provider)
t.add_inputs([TxInput(unspent, sighash=SIGHASH.NONE_FORKID) for unspent in unspents])
t.sign()

# it's good to add any outputs here, no need to sign, can broadcast directly
print(t.add_change().broadcast())
