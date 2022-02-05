from typing import List, Union

from bsvlib import Key, Unspent, Transaction, TxOutput
from bsvlib.constants import Chain
from bsvlib.script import BareMultisigScriptType, Script
from bsvlib.service import WhatsOnChain

k1 = Key('cVwfreZB3i8iv9JpdSStd9PWhZZGGJCFLS4rEKWfbkahibwhticA')
k2 = Key('93UnxexmsTYCmDJdctz4zacuwxQd5prDmH6rfpEyKkQViAVA3me')
provider = WhatsOnChain(Chain.TEST)

t = Transaction(provider=provider)
t.add_inputs(Unspent.get_unspents(provider=provider, private_keys=[k1]))
# add a 2-of-3 multi-sig output
public_keys: List[Union[str, bytes]] = [k1.public_key().hex(compressed=False), Key().public_key().hex(), k2.public_key().serialize()]
multisig_script: Script = BareMultisigScriptType.locking(public_keys, 2)
t.add_output(TxOutput(out=multisig_script, satoshi=1000, script_type=BareMultisigScriptType()))
txid = t.add_change().sign().broadcast()
print(f'create multisig - {txid}')

# send the multi-sig unspent we just created
unspent = Unspent(txid=txid, vout=0, satoshi=1000, private_keys=[k1, k2], locking_script=multisig_script, script_type=BareMultisigScriptType())
txid = Transaction(provider=provider).add_input(unspent).add_change(k1.address()).sign().broadcast()
print(f'spend multisig - {txid}')
