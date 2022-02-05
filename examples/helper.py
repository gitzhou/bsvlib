from bsvlib import Key, Transaction, Unspent, TxOutput, TxInput
from bsvlib.constants import Chain
from bsvlib.script import Script
from bsvlib.service import WhatsOnChain


def create_then_spend(locking: Script, unlocking: Script):
    """
    create an unspent with the specific locking script, then spend it with the specific unlocking script
    """
    provider = WhatsOnChain(Chain.TEST)
    k = Key('cVwfreZB3i8iv9JpdSStd9PWhZZGGJCFLS4rEKWfbkahibwhticA')

    t = Transaction(provider=provider)
    t.add_inputs(Unspent.get_unspents(provider=provider, private_keys=[k]))
    txid = t.add_output(TxOutput(locking, 1000)).add_change(k.address()).sign().broadcast()
    print(f'create - {txid}')

    unspent = Unspent(txid=txid, vout=0, satoshi=1000, locking_script=locking)
    t = Transaction(provider=provider)
    t.add_input(TxInput(unspent, unlocking_script=unlocking))
    txid = t.add_output(TxOutput(k.address(), 800)).broadcast()
    print(f'spend - {txid}')
