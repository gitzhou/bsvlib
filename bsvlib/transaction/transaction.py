import math
from io import BytesIO
from typing import List, Optional, Union

from .script import Script
from .unspent import Unspent
from ..constants import SigHash, TxOutType, Chain
from ..constants import TRANSACTION_VERSION, TRANSACTION_LOCKTIME, TRANSACTION_SEQUENCE, TRANSACTION_FEE_RATE, P2PKH_DUST_LIMIT
from ..hash import hash256
from ..keys import PrivateKey
from ..service.provider import Provider
from ..service.service import Service
from ..service.whatsonchain import WhatsOnChain
from ..utils import unsigned_to_varint


class TxInput:
    def __init__(self, unspent: Unspent, private_key: Optional[PrivateKey] = None, unlocking_script: Optional[Script] = None,
                 sequence: int = TRANSACTION_SEQUENCE, sighash: SigHash = SigHash.ALL):
        self.txid: str = unspent.txid
        self.vout: int = unspent.vout
        self.satoshi: int = unspent.satoshi
        self.height: int = unspent.height
        self.confirmation: int = unspent.confirmation
        self.private_key: Optional[PrivateKey] = private_key or unspent.private_key or None
        self.unspent_type: TxOutType = unspent.unspent_type
        self.locking_script: Script = unspent.locking_script

        self.unlocking_script: Script = unlocking_script
        self.sequence: int = sequence
        self.sighash: SigHash = sighash

    def serialize(self) -> bytes:
        stream = BytesIO()
        stream.write(bytes.fromhex(self.txid)[::-1])
        stream.write(self.vout.to_bytes(4, 'little'))
        stream.write(self.unlocking_script.byte_length_varint() if self.unlocking_script else b'\x00')
        stream.write(self.unlocking_script.serialize() if self.unlocking_script else b'')
        stream.write(self.sequence.to_bytes(4, 'little'))
        return stream.getvalue()

    def __repr__(self) -> str:
        return f'<TxInput outpoint={self.txid}:{self.vout} satoshi={self.satoshi} locking_script={self.locking_script}>'


class TxOutput:
    def __init__(self, out: Union[str, List[Union[str, bytes]], Script], satoshi: int = 0, out_type: Optional[TxOutType] = None):
        self.satoshi = satoshi
        if isinstance(out, str):
            # from address
            self.locking_script: Script = Script.p2pkh_locking(out)
            self.out_type: TxOutType = TxOutType.P2PKH
        elif isinstance(out, List):
            # from list of pushdata
            self.locking_script: Script = Script.op_return(out)
            self.out_type: TxOutType = TxOutType.OP_RETURN
        elif isinstance(out, Script):
            # from locking script
            self.locking_script: Script = out
            self.out_type: TxOutType = out_type or TxOutType.UNKNOWN
        else:
            raise TypeError('unsupported transaction output type')

    def serialize(self) -> bytes:
        return self.satoshi.to_bytes(8, 'little') + self.locking_script.byte_length_varint() + self.locking_script.serialize()


class Transaction:
    def __init__(self, tx_inputs: Optional[List[TxInput]] = None, tx_outputs: Optional[List[TxOutput]] = None,
                 version: int = TRANSACTION_VERSION, locktime: int = TRANSACTION_LOCKTIME, fee_rate: Optional[float] = None,
                 chain: Chain = Chain.MAIN, provider: Provider = None):
        self.tx_inputs: List[TxInput] = tx_inputs or []
        self.tx_outputs: List[TxOutput] = tx_outputs or []
        self.version: int = version
        self.locktime: int = locktime
        self.fee_rate: float = fee_rate if fee_rate is not None else TRANSACTION_FEE_RATE
        self.chain: Chain = chain
        self.provider: Provider = provider or WhatsOnChain(chain)

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

    def inputs(self) -> List[TxInput]:
        return self.tx_inputs

    def outputs(self) -> List[TxOutput]:
        return self.tx_outputs

    def add_input(self, tx_input: Union[TxInput, Unspent]) -> 'Transaction':
        if isinstance(tx_input, TxInput):
            self.tx_inputs.append(tx_input)
        elif isinstance(tx_input, Unspent):
            self.tx_inputs.append(TxInput(tx_input))
        else:
            raise TypeError('unsupported transaction input type')
        return self

    def add_inputs(self, tx_inputs: List[Union[TxInput, Unspent]]) -> 'Transaction':
        for tx_input in tx_inputs:
            self.add_input(tx_input)
        return self

    def add_output(self, tx_output: TxOutput) -> 'Transaction':
        self.tx_outputs.append(tx_output)
        return self

    def add_outputs(self, tx_outputs: List[TxOutput]) -> 'Transaction':
        for tx_output in tx_outputs:
            self.add_output(tx_output)
        return self

    def hex(self) -> str:
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

    def digest(self) -> List[bytes]:
        """
        :returns: the digest of unsigned transaction
        """
        digest = []
        for tx_input in self.tx_inputs:
            if tx_input.sighash == SigHash.ALL:
                hash_prevouts = hash256(b''.join([bytes.fromhex(tx_in.txid)[::-1] + tx_in.vout.to_bytes(4, 'little') for tx_in in self.tx_inputs]))
                hash_sequence = hash256(b''.join([tx_in.sequence.to_bytes(4, 'little') for tx_in in self.tx_inputs]))
                hash_outputs = hash256(b''.join([tx_out.serialize() for tx_out in self.tx_outputs]))
            else:
                # TODO support other sighash
                raise ValueError(f'unsupported sighash {tx_input.sighash}')
            digest.append(self._digest(tx_input, hash_prevouts, hash_sequence, hash_outputs))
        return digest

    def sign(self) -> 'Transaction':
        """
        sign all inputs according to their unspent type
        """
        digests = self.digest()
        for i in range(len(self.tx_inputs)):
            tx_input = self.tx_inputs[i]
            if tx_input.unspent_type == TxOutType.P2PKH:
                # sign as p2pkh
                if not tx_input.private_key:
                    raise ValueError(f"{tx_input} doesn't have a private key")
                signature: bytes = tx_input.private_key.sign(digests[i])
                public_key: bytes = tx_input.private_key.public_key().serialize()
                tx_input.unlocking_script = Script.p2pkh_unlocking(signature, public_key, tx_input.sighash)
            elif tx_input.unlocking_script:
                # still good, unlocking script is ready
                continue
            else:
                # don't know how to sign
                # TODO support other transaction out type
                raise ValueError(f'unsupported unspent type {tx_input.unspent_type}')
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

    def estimated_byte_length(self) -> int:
        """
        :returns: estimated byte length of this transaction after signing
        """
        estimated_length = 4 + len(unsigned_to_varint(len(self.tx_inputs))) + len(unsigned_to_varint(len(self.tx_outputs))) + 4
        for tx_input in self.tx_inputs:
            if tx_input.unspent_type == TxOutType.P2PKH:
                if not tx_input.private_key:
                    raise ValueError(f"can't estimate byte length for {tx_input} without a private key")
                estimated_length += 148 if tx_input.private_key.compressed else 180
            else:
                # TODO support other unspent type
                raise ValueError(f"can't estimate byte length for unspent type {tx_input.unspent_type}")
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
        size_increased = 34 + len(unsigned_to_varint(len(self.tx_outputs) + 1)) - len(unsigned_to_varint(len(self.tx_outputs)))
        fee_expected = math.ceil(self.fee_rate * (self.estimated_byte_length() + size_increased))
        fee_overpaid = self.fee() - fee_expected
        if fee_overpaid >= P2PKH_DUST_LIMIT:
            change_output: Optional[TxOutput] = None
            if not change_address:
                for tx_input in self.tx_inputs:
                    if tx_input.unspent_type == TxOutType.P2PKH:
                        change_output = TxOutput(out=tx_input.locking_script, satoshi=fee_overpaid)
                        break
            else:
                change_output = TxOutput(out=change_address, satoshi=fee_overpaid)
            assert change_output, "can't parse any address from transaction inputs"
            self.add_output(change_output)
        return self

    def broadcast(self) -> Optional[str]:
        return Service(self.chain, self.provider).broadcast(self.hex())
