import time
from typing import List, Union

from bsvlib import Key, Unspent, Transaction, TxOutput
from bsvlib.constants import Chain
from bsvlib.script import BareMultisigScriptType, Script
from bsvlib.service import WhatsOnChain

k1 = Key('cVwfreZB3i8iv9JpdSStd9PWhZZGGJCFLS4rEKWfbkahibwhticA')
k2 = Key('93UnxexmsTYCmDJdctz4zacuwxQd5prDmH6rfpEyKkQViAVA3me')
provider = WhatsOnChain(Chain.TEST)
unspents = Unspent.get_unspents(provider=provider, private_keys=[k1])

# a 2-of-3 multi-sig output
public_keys: List[Union[str, bytes]] = [k1.public_key().hex(), Key().public_key().hex(), k2.public_key().serialize()]
multisig_script: Script = BareMultisigScriptType.locking(public_keys, 2)
output = TxOutput(out=multisig_script, satoshi=1000, script_type=BareMultisigScriptType())

# create a multi-sig output
t = Transaction(provider=provider).add_inputs(unspents).add_output(output).add_change().sign()
r = t.broadcast()
print(f'create multisig - {r}')
assert r.propagated
time.sleep(2)

# send the multi-sig unspent we just created
unspent = t.to_unspent(0, private_keys=[k1, k2])
r = Transaction(provider=provider).add_input(unspent).add_change(k1.address()).sign().broadcast()
print(f'spend multisig - {r}')
