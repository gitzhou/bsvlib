import time

from bsvlib import Key, Transaction, Unspent, TxOutput, TxInput
from bsvlib.constants import Chain
from bsvlib.script import Script
from bsvlib.service import WhatsOnChain


def create_then_spend(locking: Script, unlocking: Script):
    """
    create an unspent with the specific locking script, then spend it with the specific unlocking script
    """
    k = Key('cVwfreZB3i8iv9JpdSStd9PWhZZGGJCFLS4rEKWfbkahibwhticA')
    provider = WhatsOnChain(Chain.TEST)
    unspents = Unspent.get_unspents(provider=provider, private_keys=[k])

    t = Transaction(provider=provider).add_inputs(unspents).add_output(TxOutput(locking, 1000)).add_change(k.address()).sign()
    r = t.broadcast()
    print(f'create - {r}')
    assert r.propagated

    time.sleep(2)
    _input = TxInput(t.to_unspent(0), unlocking_script=unlocking)
    r = Transaction(provider=provider).add_input(_input).add_output(TxOutput(k.address(), 800)).broadcast()
    print(f'spend - {r}')
