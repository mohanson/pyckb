import ckb.config
import ckb.core
import ckb.rpc
import itertools
import json


class Scw:
    def __init__(self, prikey: int):
        self.prikey = ckb.core.PriKey(prikey)
        self.pubkey = self.prikey.pubkey()
        self.script = ckb.core.Script(
            ckb.config.current.scripts.secp256k1_blake160.code_hash,
            ckb.config.current.scripts.secp256k1_blake160.hash_type,
            ckb.core.hash(self.pubkey.pack())[:20]
        )
        self.addr = ckb.core.address_encode(self.script)

    def __repr__(self):
        return json.dumps(self.json())

    def __eq__(self, other):
        a = self.prikey == other.prikey
        b = self.pubkey == other.pubkey
        c = self.script == other.script
        return a and b and c

    def json(self):
        return {
            'prikey': self.prikey.json(),
            'pubkey': self.pubkey.json(),
            'script': self.script.json(),
            'addr': self.addr,
        }

    def livecell(self):
        return ckb.rpc.get_cells_iter({
            'script': self.script.json(),
            'script_type': 'lock',
            'filter': {
                'script_len_range': ['0x0', '0x1']
            }
        })

    def capacity(self):
        return int(ckb.rpc.get_cells_capacity({
            'script': self.script.json(),
            'script_type': 'lock',
            'filter': {
                'script_len_range': ['0x0', '0x1']
            }
        })['capacity'], 16)

    def transfer(self, script: ckb.core.Script, capacity: int):
        assert capacity >= 61 * 100000000
        assert self.capacity() > capacity
        accept_script = script
        change_script = self.script
        sender_capacity = 0
        accept_capacity = capacity
        change_capacity = 0
        tx = ckb.core.Transaction(ckb.core.TransactionRaw(0, [], [], [], [], []), [])
        tx.raw.cell_deps.append(ckb.core.CellDep(
            ckb.core.OutPoint(
                ckb.config.current.scripts.secp256k1_blake160.cell_dep.out_point.tx_hash,
                ckb.config.current.scripts.secp256k1_blake160.cell_dep.out_point.index
            ),
            ckb.config.current.scripts.secp256k1_blake160.cell_dep.dep_type,
        ))
        tx.raw.outputs.append(ckb.core.CellOutput(accept_capacity, accept_script, None))
        tx.raw.outputs_data.append(bytearray())
        tx.raw.outputs.append(ckb.core.CellOutput(change_capacity, change_script, None))
        tx.raw.outputs_data.append(bytearray())
        for cell in itertools.islice(self.livecell(), 256):
            cell_out_point = ckb.core.OutPoint(
                bytearray.fromhex(cell['out_point']['tx_hash'][2:]),
                int(cell['out_point']['index'], 16)
            )
            cell_capacity = int(cell['output']['capacity'], 16)
            cell_input = ckb.core.CellInput(0, cell_out_point)
            sender_capacity += cell_capacity
            tx.raw.inputs.append(cell_input)
            if len(tx.witnesses) == 0:
                tx.witnesses.append(ckb.core.WitnessArgs(bytearray([0 for _ in range(65)]), None, None).pack())
            else:
                tx.witnesses.append(bytearray())
            change_capacity = sender_capacity - accept_capacity - len(tx.pack()) - 4
            if change_capacity >= 61 * 100000000:
                break
        assert change_capacity >= 61 * 100000000
        tx.raw.outputs[1].capacity = change_capacity
        sign_data = bytearray()
        sign_data.extend(tx.raw.hash())
        for witness in tx.witnesses:
            sign_data.extend(len(witness).to_bytes(8, 'little'))
            sign_data.extend(witness)
        sign_data = ckb.core.hash(sign_data)
        sign = self.prikey.sign(sign_data)
        tx.witnesses[0] = ckb.core.WitnessArgs(sign, None, None).pack()
        return ckb.rpc.send_transaction(tx.json(), 'well_known_scripts_only')

    def transfer_max(self, script: ckb.core.Script):
        assert self.capacity() > 0
        accept_script = script
        sender_capacity = 0
        accept_capacity = 0
        tx = ckb.core.Transaction(ckb.core.TransactionRaw(0, [], [], [], [], []), [])
        tx.raw.cell_deps.append(ckb.core.CellDep(
            ckb.core.OutPoint(
                ckb.config.current.scripts.secp256k1_blake160.cell_dep.out_point.tx_hash,
                ckb.config.current.scripts.secp256k1_blake160.cell_dep.out_point.index
            ),
            ckb.config.current.scripts.secp256k1_blake160.cell_dep.dep_type,
        ))
        tx.raw.outputs.append(ckb.core.CellOutput(accept_capacity, accept_script, None))
        tx.raw.outputs_data.append(bytearray())
        for cell in itertools.islice(self.livecell(), 256):
            cell_out_point = ckb.core.OutPoint(
                bytearray.fromhex(cell['out_point']['tx_hash'][2:]),
                int(cell['out_point']['index'], 16)
            )
            cell_capacity = int(cell['output']['capacity'], 16)
            cell_input = ckb.core.CellInput(0, cell_out_point)
            sender_capacity += cell_capacity
            tx.raw.inputs.append(cell_input)
            if len(tx.witnesses) == 0:
                tx.witnesses.append(ckb.core.WitnessArgs(bytearray([0 for _ in range(65)]), None, None).pack())
            else:
                tx.witnesses.append(bytearray())
        accept_capacity = sender_capacity - len(tx.pack()) - 4
        tx.raw.outputs[0].capacity = accept_capacity
        sign_data = bytearray()
        sign_data.extend(tx.raw.hash())
        for witness in tx.witnesses:
            sign_data.extend(len(witness).to_bytes(8, 'little'))
            sign_data.extend(witness)
        sign_data = ckb.core.hash(sign_data)
        sign = self.prikey.sign(sign_data)
        tx.witnesses[0] = ckb.core.WitnessArgs(sign, None, None).pack()
        tx_hash = ckb.rpc.send_transaction(tx.json(), 'well_known_scripts_only')
        return tx_hash

    def converge(self):
        # Merge the smallest 256 livecells.
        assert self.capacity() > 0
        livecell = list(itertools.islice(self.livecell(), 256))
        if len(livecell) < 256:
            return None
        return self.heritage(self.script)
