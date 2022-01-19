import math
from io import BytesIO
from typing import List, Optional, Union, Dict, Any

from .unspent import Unspent
from ..constants import SIGHASH, Chain
from ..constants import TRANSACTION_VERSION, TRANSACTION_LOCKTIME, TRANSACTION_SEQUENCE, TRANSACTION_FEE_RATE, P2PKH_DUST_LIMIT
from ..hash import hash256
from ..keys import PrivateKey
from ..script.script import Script
from ..script.type import ScriptType, P2pkhScriptType, OpReturnScriptType
from ..service.provider import Provider
from ..service.service import Service
from ..service.whatsonchain import WhatsOnChain
from ..utils import unsigned_to_varint, serialize_ecdsa_der


class InsufficientFundsError(ValueError):
    pass


class TxInput:

    def __init__(self, unspent: Unspent, private_keys: Optional[List[PrivateKey]] = None, unlocking_script: Optional[Script] = None,
                 sequence: int = TRANSACTION_SEQUENCE, sighash: SIGHASH = SIGHASH.ALL_FORKID):
        self.txid: str = unspent.txid
        self.vout: int = unspent.vout
        self.satoshi: int = unspent.satoshi
        self.height: int = unspent.height
        self.confirmation: int = unspent.confirmation
        self.private_keys: List[PrivateKey] = private_keys or unspent.private_keys or []
        self.script_type: ScriptType = unspent.script_type
        self.locking_script: Script = unspent.locking_script

        self.unlocking_script: Script = unlocking_script
        self.sequence: int = sequence
        self.sighash: SIGHASH = sighash

    def serialize(self) -> bytes:
        stream = BytesIO()
        stream.write(bytes.fromhex(self.txid)[::-1])
        stream.write(self.vout.to_bytes(4, 'little'))
        stream.write(self.unlocking_script.byte_length_varint() if self.unlocking_script else b'\x00')
        stream.write(self.unlocking_script.serialize() if self.unlocking_script else b'')
        stream.write(self.sequence.to_bytes(4, 'little'))
        return stream.getvalue()

    def __repr__(self) -> str:  # pragma: no cover
        return f'<TxInput outpoint={self.txid}:{self.vout} satoshi={self.satoshi} locking_script={self.locking_script}>'


class TxOutput:

    def __init__(self, out: Union[str, List[Union[str, bytes]], Script], satoshi: int = 0, script_type: Optional[ScriptType] = None):
        self.satoshi = satoshi
        if isinstance(out, str):
            # from address
            self.locking_script: Script = P2pkhScriptType.locking(out)
            self.script_type: ScriptType = P2pkhScriptType()
        elif isinstance(out, List):
            # from list of pushdata
            self.locking_script: Script = OpReturnScriptType.locking(out)
            self.script_type: ScriptType = OpReturnScriptType()
        elif isinstance(out, Script):
            # from locking script
            self.locking_script: Script = out
            self.script_type: ScriptType = script_type
        else:
            raise TypeError('unsupported transaction output type')

    def serialize(self) -> bytes:
        return self.satoshi.to_bytes(8, 'little') + self.locking_script.byte_length_varint() + self.locking_script.serialize()


class Transaction:

    def __init__(self, tx_inputs: Optional[List[TxInput]] = None, tx_outputs: Optional[List[TxOutput]] = None,
                 version: int = TRANSACTION_VERSION, locktime: int = TRANSACTION_LOCKTIME, fee_rate: Optional[float] = None,
                 chain: Chain = Chain.MAIN, provider: Provider = None, **kwargs):
        self.tx_inputs: List[TxInput] = tx_inputs or []
        self.tx_outputs: List[TxOutput] = tx_outputs or []
        self.version: int = version
        self.locktime: int = locktime
        self.fee_rate: float = fee_rate if fee_rate is not None else TRANSACTION_FEE_RATE
        self.chain: Chain = chain
        self.provider: Provider = provider or WhatsOnChain(chain)
        self.kwargs: Dict[str, Any] = dict(**kwargs) or {}

    def serialize(self) -> bytes:
        raw = self.version.to_bytes(4, 'little')
        raw += unsigned_to_varint(len(self.tx_inputs))
        for tx_input in self.tx_inputs:
            raw += tx_input.serialize()
        raw += unsigned_to_varint(len(self.tx_outputs))
        for tx_output in self.tx_outputs:
            raw += tx_output.serialize()
        raw += self.locktime.to_bytes(4, 'little')
        return raw

    def add_input(self, tx_input: Union[TxInput, Unspent]) -> 'Transaction':  # pragma: no cover
        if isinstance(tx_input, TxInput):
            self.tx_inputs.append(tx_input)
        elif isinstance(tx_input, Unspent):
            self.tx_inputs.append(TxInput(tx_input))
        else:
            raise TypeError('unsupported transaction input type')
        return self

    def add_inputs(self, tx_inputs: List[Union[TxInput, Unspent]]) -> 'Transaction':  # pragma: no cover
        for tx_input in tx_inputs:
            self.add_input(tx_input)
        return self

    def add_output(self, tx_output: TxOutput) -> 'Transaction':  # pragma: no cover
        self.tx_outputs.append(tx_output)
        return self

    def add_outputs(self, tx_outputs: List[TxOutput]) -> 'Transaction':  # pragma: no cover
        for tx_output in tx_outputs:
            self.add_output(tx_output)
        return self

    def hex(self) -> str:  # pragma: no cover
        return self.serialize().hex()

    raw = hex

    def txid(self) -> str:
        return hash256(self.serialize())[::-1].hex()

    def _digest(self, tx_input: TxInput, hash_prevouts: bytes, hash_sequence: bytes, hash_outputs: bytes) -> bytes:
        """
        BIP-143 https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki
         1. nVersion of the transaction (4-byte little endian)
         2. hashPrevouts (32-byte hash)
         3. hashSequence (32-byte hash)
         4. outpoint (32-byte hash + 4-byte little endian)
         5. scriptCode of the input (serialized as scripts inside CTxOuts)
         6. value of the output spent by this input (8-byte little endian)
         7. nSequence of the input (4-byte little endian)
         8. hashOutputs (32-byte hash)
         9. nLocktime of the transaction (4-byte little endian)
        10. sighash type of the signature (4-byte little endian)
        """
        stream = BytesIO()
        # 1
        stream.write(self.version.to_bytes(4, 'little'))
        # 2
        stream.write(hash_prevouts)
        # 3
        stream.write(hash_sequence)
        # 4
        stream.write(bytes.fromhex(tx_input.txid)[::-1])
        stream.write(tx_input.vout.to_bytes(4, 'little'))
        # 5
        stream.write(tx_input.locking_script.byte_length_varint())
        stream.write(tx_input.locking_script.serialize())
        # 6
        stream.write(tx_input.satoshi.to_bytes(8, 'little'))
        # 7
        stream.write(tx_input.sequence.to_bytes(4, 'little'))
        # 8
        stream.write(hash_outputs)
        # 9
        stream.write(self.locktime.to_bytes(4, 'little'))
        # 10
        stream.write(tx_input.sighash.to_bytes(4, 'little'))
        return stream.getvalue()

    def digests(self) -> List[bytes]:
        """
        :returns: the digests of unsigned transaction
        """
        _hash_prevouts = hash256(b''.join([bytes.fromhex(tx_input.txid)[::-1] + tx_input.vout.to_bytes(4, 'little') for tx_input in self.tx_inputs]))
        _hash_sequence = hash256(b''.join([tx_input.sequence.to_bytes(4, 'little') for tx_input in self.tx_inputs]))
        _hash_outputs = hash256(b''.join([tx_output.serialize() for tx_output in self.tx_outputs]))
        digests = []
        for i in range(len(self.tx_inputs)):
            sighash = self.tx_inputs[i].sighash
            # hash previous outs
            if not sighash & SIGHASH.ANYONECANPAY:
                # if anyone can pay is not set
                hash_prevouts = _hash_prevouts
            else:
                hash_prevouts = b'\x00' * 32
            # hash sequence
            if not sighash & SIGHASH.ANYONECANPAY and sighash & 0x1f != SIGHASH.SINGLE and sighash & 0x1f != SIGHASH.NONE:
                # if none of anyone can pay, single, none is set
                hash_sequence = _hash_sequence
            else:
                hash_sequence = b'\x00' * 32
            # hash outputs
            if sighash & 0x1f != SIGHASH.SINGLE and sighash & 0x1f != SIGHASH.NONE:
                # if neither single nor none
                hash_outputs = _hash_outputs
            elif sighash & 0x1f == SIGHASH.SINGLE and i < len(self.tx_outputs):
                # if single and the input index is smaller than the number of outputs
                hash_outputs = hash256(self.tx_outputs[i].serialize())
            else:
                hash_outputs = b'\x00' * 32
            digests.append(self._digest(self.tx_inputs[i], hash_prevouts, hash_sequence, hash_outputs))
        return digests

    def digest(self, index: int) -> bytes:
        """
        :returns: digest of the input specified by index
        """
        assert 0 <= index < len(self.tx_inputs), f'index out of range [0, {len(self.tx_inputs)})'
        return self.digests()[index]

    def sign(self, bypass: bool = True, **kwargs) -> 'Transaction':  # pragma: no cover
        """
        :bypass: if True then ONLY sign inputs which unlocking script is empty, otherwise sign all the inputs
        sign all inputs according to their script type
        """
        digests = self.digests()
        for i in range(len(self.tx_inputs)):
            tx_input = self.tx_inputs[i]
            if not tx_input.unlocking_script or not bypass:
                signatures: List[bytes] = [serialize_ecdsa_der(private_key.sign(digests[i])) for private_key in tx_input.private_keys]
                payload = {'signatures': signatures, 'private_keys': tx_input.private_keys, 'sighash': tx_input.sighash}
                tx_input.unlocking_script = tx_input.script_type.unlocking(**payload, **self.kwargs, **kwargs)
        return self

    def satoshi_total_in(self) -> int:
        return sum([tx_input.satoshi for tx_input in self.tx_inputs])

    def satoshi_total_out(self) -> int:
        return sum([tx_output.satoshi for tx_output in self.tx_outputs])

    def fee(self) -> int:
        """
        :returns: actual fee paid of this transaction under the current state
        """
        return self.satoshi_total_in() - self.satoshi_total_out()

    def byte_length(self) -> int:
        """
        :returns: actual byte length of this transaction under the current state
        """
        return len(self.serialize())

    size = byte_length

    def estimated_byte_length(self, **kwargs) -> int:
        """
        :returns: estimated byte length of this transaction after signing
        """
        estimated_length = 4 + len(unsigned_to_varint(len(self.tx_inputs))) + len(unsigned_to_varint(len(self.tx_outputs))) + 4
        for tx_input in self.tx_inputs:
            if not tx_input.private_keys:
                raise ValueError(f"can't estimate byte length for {tx_input} without private keys")
            estimated_length += 41 + tx_input.script_type.estimated_unlocking_byte_length(private_keys=tx_input.private_keys, **self.kwargs, **kwargs)
        for tx_output in self.tx_outputs:
            estimated_length += 8 + len(tx_output.locking_script.byte_length_varint()) + tx_output.locking_script.byte_length()
        return estimated_length

    estimated_size = estimated_byte_length

    def estimated_fee(self) -> int:
        """
        :returns: estimated fee of this transaction after signing
        """
        return math.ceil(self.fee_rate * self.estimated_byte_length())

    def add_change(self, change_address: Optional[str] = None) -> 'Transaction':
        # byte length increased after adding a P2PKH change output
        size_increased = 34 + len(unsigned_to_varint(len(self.tx_outputs) + 1)) - len(unsigned_to_varint(len(self.tx_outputs)))
        # then we know the estimated byte length after signing, of this transaction with a change output
        fee_expected = math.ceil(self.fee_rate * (self.estimated_byte_length() + size_increased))
        fee_overpaid = self.fee() - fee_expected
        if fee_overpaid >= P2PKH_DUST_LIMIT:
            change_output: Optional[TxOutput] = None
            if not change_address:
                for tx_input in self.tx_inputs:  # pragma: no cover
                    if tx_input.script_type == P2pkhScriptType():
                        change_output = TxOutput(out=tx_input.locking_script, satoshi=fee_overpaid)
                        break
            else:
                change_output = TxOutput(out=change_address, satoshi=fee_overpaid)
            assert change_output, "can't parse any address from transaction inputs"
            self.add_output(change_output)
        return self

    def broadcast(self) -> Optional[str]:  # pragma: no cover
        if self.fee() < self.estimated_fee():
            raise InsufficientFundsError(f'require {self.estimated_fee() + self.satoshi_total_out()} satoshi but only {self.satoshi_total_in()}')
        return Service(self.chain, self.provider).broadcast(self.hex())
