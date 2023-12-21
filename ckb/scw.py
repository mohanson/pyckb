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
            ckb.config.current.script.secp256k1_blake160.code_hash,
            ckb.config.current.script.secp256k1_blake160.hash_type,
            ckb.core.hash(self.pubkey.molecule())[:20]
        )
        self.addr = ckb.core.address_encode(self.script)

    def __repr__(self):
        return json.dumps(self.json())

    def __eq__(self, other):
        a = self.prikey == other.prikey
        b = self.pubkey == other.pubkey
        c = self.script == other.script
        d = self.addr == other.addr
        return a and b and c and d

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
        assert capacity >= 61 * ckb.core.shannon
        assert self.capacity() > capacity
        sender_capacity = 0
        accept_capacity = capacity
        accept_script = script
        change_capacity = 0
        change_script = self.script
        tx = ckb.core.Transaction(ckb.core.TransactionRaw(0, [], [], [], [], []), [])
        tx.raw.cell_deps.append(ckb.core.CellDep.conf_read(ckb.config.current.script.secp256k1_blake160.cell_dep))
        tx.raw.outputs.append(ckb.core.CellOutput(accept_capacity, accept_script, None))
        tx.raw.outputs.append(ckb.core.CellOutput(change_capacity, change_script, None))
        tx.raw.outputs_data.append(bytearray())
        tx.raw.outputs_data.append(bytearray())
        for cell in itertools.islice(self.livecell(), 256):
            cell_out_point = ckb.core.OutPoint.json_read(cell['out_point'])
            cell_capacity = int(cell['output']['capacity'], 16)
            cell_input = ckb.core.CellInput(0, cell_out_point)
            sender_capacity += cell_capacity
            tx.raw.inputs.append(cell_input)
            if len(tx.witnesses) == 0:
                tx.witnesses.append(ckb.core.WitnessArgs(bytearray([0] * 65), None, None).molecule())
            else:
                tx.witnesses.append(bytearray())
            change_capacity = sender_capacity - accept_capacity - len(tx.molecule()) - 4
            if change_capacity >= 61 * ckb.core.shannon:
                break
        assert change_capacity >= 61 * ckb.core.shannon
        tx.raw.outputs[1].capacity = change_capacity
        sign_data = bytearray()
        sign_data.extend(tx.raw.hash())
        for witness in tx.witnesses:
            sign_data.extend(len(witness).to_bytes(8, 'little'))
            sign_data.extend(witness)
        sign_data = ckb.core.hash(sign_data)
        sign = self.prikey.sign(sign_data)
        tx.witnesses[0] = ckb.core.WitnessArgs(sign, None, None).molecule()
        return ckb.rpc.send_transaction(tx.json(), 'well_known_scripts_only')

    def transfer_all(self, script: ckb.core.Script):
        assert self.capacity() > 0
        sender_capacity = 0
        accept_capacity = 0
        accept_script = script
        tx = ckb.core.Transaction(ckb.core.TransactionRaw(0, [], [], [], [], []), [])
        tx.raw.cell_deps.append(ckb.core.CellDep.conf_read(ckb.config.current.script.secp256k1_blake160.cell_dep))
        tx.raw.outputs.append(ckb.core.CellOutput(accept_capacity, accept_script, None))
        tx.raw.outputs_data.append(bytearray())
        for cell in itertools.islice(self.livecell(), 256):
            cell_out_point = ckb.core.OutPoint.json_read(cell['out_point'])
            cell_capacity = int(cell['output']['capacity'], 16)
            cell_input = ckb.core.CellInput(0, cell_out_point)
            sender_capacity += cell_capacity
            tx.raw.inputs.append(cell_input)
            if len(tx.witnesses) == 0:
                tx.witnesses.append(ckb.core.WitnessArgs(bytearray([0] * 65), None, None).molecule())
            else:
                tx.witnesses.append(bytearray())
        accept_capacity = sender_capacity - len(tx.molecule()) - 4
        tx.raw.outputs[0].capacity = accept_capacity
        sign_data = bytearray()
        sign_data.extend(tx.raw.hash())
        for witness in tx.witnesses:
            sign_data.extend(len(witness).to_bytes(8, 'little'))
            sign_data.extend(witness)
        sign_data = ckb.core.hash(sign_data)
        sign = self.prikey.sign(sign_data)
        tx.witnesses[0] = ckb.core.WitnessArgs(sign, None, None).molecule()
        return ckb.rpc.send_transaction(tx.json(), 'well_known_scripts_only')

    def script_deploy(self, script: ckb.core.Script, data: bytearray):
        sender_capacity = 0
        accept_capacity = (61 + len(data)) * ckb.core.shannon
        accept_script = script
        change_capacity = 0
        change_script = self.script
        tx = ckb.core.Transaction(ckb.core.TransactionRaw(0, [], [], [], [], []), [])
        tx.raw.cell_deps.append(ckb.core.CellDep.conf_read(ckb.config.current.script.secp256k1_blake160.cell_dep))
        tx.raw.outputs.append(ckb.core.CellOutput(accept_capacity, accept_script, None))
        tx.raw.outputs.append(ckb.core.CellOutput(change_capacity, change_script, None))
        tx.raw.outputs_data.append(data)
        tx.raw.outputs_data.append(bytearray())
        for cell in itertools.islice(self.livecell(), 256):
            cell_out_point = ckb.core.OutPoint.json_read(cell['out_point'])
            cell_capacity = int(cell['output']['capacity'], 16)
            cell_input = ckb.core.CellInput(0, cell_out_point)
            sender_capacity += cell_capacity
            tx.raw.inputs.append(cell_input)
            if len(tx.witnesses) == 0:
                tx.witnesses.append(ckb.core.WitnessArgs(bytearray([0] * 65), None, None).molecule())
            else:
                tx.witnesses.append(bytearray())
            change_capacity = sender_capacity - accept_capacity - len(tx.molecule()) - 4
            if change_capacity >= 61 * ckb.core.shannon:
                break
        assert change_capacity >= 61 * ckb.core.shannon
        tx.raw.outputs[1].capacity = change_capacity
        sign_data = bytearray()
        sign_data.extend(tx.raw.hash())
        for witness in tx.witnesses:
            sign_data.extend(len(witness).to_bytes(8, 'little'))
            sign_data.extend(witness)
        sign_data = ckb.core.hash(sign_data)
        sign = self.prikey.sign(sign_data)
        tx.witnesses[0] = ckb.core.WitnessArgs(sign, None, None).molecule()
        return ckb.rpc.send_transaction(tx.json(), 'well_known_scripts_only')

    def script_deploy_type_id(self, script: ckb.core.Script, data: bytearray):
        sender_capacity = 0
        accept_capacity = (126 + len(data)) * ckb.core.shannon
        accept_script = script
        accept_typeid = ckb.core.Script(
            bytearray.fromhex('00000000000000000000000000000000000000000000000000545950455f4944'),
            1,
            bytearray([0] * 32)
        )
        change_capacity = 0
        change_script = self.script
        tx = ckb.core.Transaction(ckb.core.TransactionRaw(0, [], [], [], [], []), [])
        tx.raw.cell_deps.append(ckb.core.CellDep.conf_read(ckb.config.current.script.secp256k1_blake160.cell_dep))
        tx.raw.outputs.append(ckb.core.CellOutput(accept_capacity, accept_script, accept_typeid))
        tx.raw.outputs.append(ckb.core.CellOutput(change_capacity, change_script, None))
        tx.raw.outputs_data.append(data)
        tx.raw.outputs_data.append(bytearray())
        for cell in itertools.islice(self.livecell(), 256):
            cell_out_point = ckb.core.OutPoint.json_read(cell['out_point'])
            cell_capacity = int(cell['output']['capacity'], 16)
            cell_input = ckb.core.CellInput(0, cell_out_point)
            sender_capacity += cell_capacity
            tx.raw.inputs.append(cell_input)
            if len(tx.witnesses) == 0:
                tx.witnesses.append(ckb.core.WitnessArgs(bytearray([0] * 65), None, None).molecule())
            else:
                tx.witnesses.append(bytearray())
            change_capacity = sender_capacity - accept_capacity - len(tx.molecule()) - 4
            if change_capacity >= 61 * ckb.core.shannon:
                break
        assert change_capacity >= 61 * ckb.core.shannon
        tx.raw.outputs[0].type.args = ckb.core.hash(tx.raw.inputs[0].molecule() + bytearray([0] * 8))
        tx.raw.outputs[1].capacity = change_capacity
        sign_data = bytearray()
        sign_data.extend(tx.raw.hash())
        for witness in tx.witnesses:
            sign_data.extend(len(witness).to_bytes(8, 'little'))
            sign_data.extend(witness)
        sign_data = ckb.core.hash(sign_data)
        sign = self.prikey.sign(sign_data)
        tx.witnesses[0] = ckb.core.WitnessArgs(sign, None, None).molecule()
        return ckb.rpc.send_transaction(tx.json(), 'passthrough')

    def script_update_type_id(self, script: ckb.core.Script, data: bytearray, out_point: ckb.core.OutPoint):
        result = ckb.rpc.get_transaction('0x' + out_point.tx_hash.hex(), None, None)
        origin = ckb.core.CellOutput.json_read(result['transaction']['outputs'][out_point.index])
        assert origin.type
        # https://github.com/nervosnetwork/ckb/tree/develop/rpc#type-indexercell
        idcell = {
            'output': origin.json(),
            'out_point': out_point.json()
        }
        sender_capacity = 0
        accept_capacity = (126 + len(data)) * ckb.core.shannon
        accept_script = script
        accept_typeid = origin.type
        change_capacity = 0
        change_script = self.script
        tx = ckb.core.Transaction(ckb.core.TransactionRaw(0, [], [], [], [], []), [])
        tx.raw.cell_deps.append(ckb.core.CellDep.conf_read(ckb.config.current.script.secp256k1_blake160.cell_dep))
        tx.raw.outputs.append(ckb.core.CellOutput(accept_capacity, accept_script, accept_typeid))
        tx.raw.outputs.append(ckb.core.CellOutput(change_capacity, change_script, None))
        tx.raw.outputs_data.append(data)
        tx.raw.outputs_data.append(bytearray())
        for cell in itertools.islice(itertools.chain([idcell], self.livecell()), 256):
            cell_out_point = ckb.core.OutPoint.json_read(cell['out_point'])
            cell_capacity = int(cell['output']['capacity'], 16)
            cell_input = ckb.core.CellInput(0, cell_out_point)
            sender_capacity += cell_capacity
            tx.raw.inputs.append(cell_input)
            if len(tx.witnesses) == 0:
                tx.witnesses.append(ckb.core.WitnessArgs(bytearray([0] * 65), None, None).molecule())
            else:
                tx.witnesses.append(bytearray())
            change_capacity = sender_capacity - accept_capacity - len(tx.molecule()) - 4
            if change_capacity >= 61 * ckb.core.shannon:
                break
        assert change_capacity >= 61 * ckb.core.shannon
        tx.raw.outputs[1].capacity = change_capacity
        sign_data = bytearray()
        sign_data.extend(tx.raw.hash())
        for witness in tx.witnesses:
            sign_data.extend(len(witness).to_bytes(8, 'little'))
            sign_data.extend(witness)
        sign_data = ckb.core.hash(sign_data)
        sign = self.prikey.sign(sign_data)
        tx.witnesses[0] = ckb.core.WitnessArgs(sign, None, None).molecule()
        return ckb.rpc.send_transaction(tx.json(), 'passthrough')

    def dao_deposit(self, capacity: int):
        # https://github.com/nervosnetwork/rfcs/blob/master/rfcs/0023-dao-deposit-withdraw/0023-dao-deposit-withdraw.md#deposit
        assert capacity >= 102 * ckb.core.shannon
        assert self.capacity() > capacity
        sender_capacity = 0
        accept_capacity = capacity
        accept_script = self.script
        accept_typeid = ckb.core.Script(
            ckb.config.current.script.dao.code_hash,
            ckb.config.current.script.dao.hash_type,
            bytearray()
        )
        change_capacity = 0
        change_script = self.script
        tx = ckb.core.Transaction(ckb.core.TransactionRaw(0, [], [], [], [], []), [])
        tx.raw.cell_deps.append(ckb.core.CellDep.conf_read(ckb.config.current.script.secp256k1_blake160.cell_dep))
        tx.raw.cell_deps.append(ckb.core.CellDep.conf_read(ckb.config.current.script.dao.cell_dep))
        tx.raw.outputs.append(ckb.core.CellOutput(accept_capacity, accept_script, accept_typeid))
        tx.raw.outputs.append(ckb.core.CellOutput(change_capacity, change_script, None))
        tx.raw.outputs_data.append(bytearray([0] * 8))
        tx.raw.outputs_data.append(bytearray())
        for cell in itertools.islice(self.livecell(), 256):
            cell_out_point = ckb.core.OutPoint.json_read(cell['out_point'])
            cell_capacity = int(cell['output']['capacity'], 16)
            cell_input = ckb.core.CellInput(0, cell_out_point)
            sender_capacity += cell_capacity
            tx.raw.inputs.append(cell_input)
            if len(tx.witnesses) == 0:
                tx.witnesses.append(ckb.core.WitnessArgs(bytearray([0] * 65), None, None).molecule())
            else:
                tx.witnesses.append(bytearray())
            change_capacity = sender_capacity - accept_capacity - len(tx.molecule()) - 4
            if change_capacity >= 61 * ckb.core.shannon:
                break
        assert change_capacity >= 61 * ckb.core.shannon
        tx.raw.outputs[1].capacity = change_capacity
        sign_data = bytearray()
        sign_data.extend(tx.raw.hash())
        for witness in tx.witnesses:
            sign_data.extend(len(witness).to_bytes(8, 'little'))
            sign_data.extend(witness)
        sign_data = ckb.core.hash(sign_data)
        sign = self.prikey.sign(sign_data)
        tx.witnesses[0] = ckb.core.WitnessArgs(sign, None, None).molecule()
        return ckb.rpc.send_transaction(tx.json(), 'well_known_scripts_only')

    def dao_prepare(self, out_point: ckb.core.OutPoint):
        # https://github.com/nervosnetwork/rfcs/blob/master/rfcs/0023-dao-deposit-withdraw/0023-dao-deposit-withdraw.md#withdraw-phase-1
        result = ckb.rpc.get_transaction('0x' + out_point.tx_hash.hex(), None, None)
        number = int(ckb.rpc.get_header(result['tx_status']['block_hash'], None)['number'], 16)
        origin = ckb.core.CellOutput.json_read(result['transaction']['outputs'][out_point.index])
        assert origin.type.code_hash == ckb.config.current.script.dao.code_hash
        assert origin.type.hash_type == ckb.config.current.script.dao.hash_type
        assert origin.type.args == bytearray()
        idcell = {
            'output': origin.json(),
            'out_point': out_point.json()
        }
        sender_capacity = 0
        accept_capacity = origin.capacity
        accept_script = origin.lock
        accept_typeid = origin.type
        change_capacity = 0
        change_script = self.script
        tx = ckb.core.Transaction(ckb.core.TransactionRaw(0, [], [], [], [], []), [])
        tx.raw.cell_deps.append(ckb.core.CellDep.conf_read(ckb.config.current.script.secp256k1_blake160.cell_dep))
        tx.raw.cell_deps.append(ckb.core.CellDep.conf_read(ckb.config.current.script.dao.cell_dep))
        tx.raw.header_deps.append(bytearray.fromhex(result['tx_status']['block_hash'][2:]))
        tx.raw.outputs.append(ckb.core.CellOutput(accept_capacity, accept_script, accept_typeid))
        tx.raw.outputs.append(ckb.core.CellOutput(change_capacity, change_script, None))
        tx.raw.outputs_data.append(number.to_bytes(8, 'little'))
        tx.raw.outputs_data.append(bytearray())
        for cell in itertools.islice(itertools.chain([idcell], self.livecell()), 256):
            cell_out_point = ckb.core.OutPoint.json_read(cell['out_point'])
            cell_capacity = int(cell['output']['capacity'], 16)
            cell_input = ckb.core.CellInput(0, cell_out_point)
            sender_capacity += cell_capacity
            tx.raw.inputs.append(cell_input)
            if len(tx.witnesses) == 0:
                tx.witnesses.append(ckb.core.WitnessArgs(bytearray([0] * 65), None, None).molecule())
            else:
                tx.witnesses.append(bytearray())
            change_capacity = sender_capacity - accept_capacity - len(tx.molecule()) - 4
            if change_capacity >= 61 * ckb.core.shannon:
                break
        assert change_capacity >= 61 * ckb.core.shannon
        tx.raw.outputs[1].capacity = change_capacity
        sign_data = bytearray()
        sign_data.extend(tx.raw.hash())
        for witness in tx.witnesses:
            sign_data.extend(len(witness).to_bytes(8, 'little'))
            sign_data.extend(witness)
        sign_data = ckb.core.hash(sign_data)
        sign = self.prikey.sign(sign_data)
        tx.witnesses[0] = ckb.core.WitnessArgs(sign, None, None).molecule()
        return ckb.rpc.send_transaction(tx.json(), 'well_known_scripts_only')

    def dao_extract(self, out_point: ckb.core.OutPoint):
        # https://github.com/nervosnetwork/rfcs/blob/master/rfcs/0023-dao-deposit-withdraw/0023-dao-deposit-withdraw.md#withdraw-phase-2
        result = ckb.rpc.get_transaction('0x' + out_point.tx_hash.hex(), None, None)
        origin = ckb.core.CellOutput.json_read(result['transaction']['outputs'][out_point.index])
        assert origin.type.code_hash == ckb.config.current.script.dao.code_hash
        assert origin.type.hash_type == ckb.config.current.script.dao.hash_type
        assert origin.type.args == bytearray()
        idcell = {
            'output': origin.json(),
            'out_point': out_point.json()
        }
        deposit_block_number_byte = bytearray.fromhex(result['transaction']['outputs_data'][out_point.index][2:])
        deposit_block_number = int.from_bytes(deposit_block_number_byte, 'little')
        deposit_block_header = ckb.rpc.get_block_by_number(deposit_block_number)['header']
        deposit_block_hash = bytearray.fromhex(deposit_block_header['hash'][2:])
        deposit_dao_ar = int.from_bytes(bytearray.fromhex(deposit_block_header['dao'][2:])[8:16], 'little')
        prepare_block_hash = bytearray.fromhex(result['tx_status']['block_hash'][2:])
        prepare_block_header = ckb.rpc.get_header('0x' + prepare_block_hash.hex(), None)
        prepare_dao_ar = int.from_bytes(bytearray.fromhex(prepare_block_header['dao'][2:])[8:16], 'little')
        sender_capacity = 0
        accept_capacity = (origin.capacity - 102) * prepare_dao_ar // deposit_dao_ar + 102
        accept_script = self.script
        change_capacity = 0
        change_script = self.script
        tx = ckb.core.Transaction(ckb.core.TransactionRaw(0, [], [], [], [], []), [])
        tx.raw.cell_deps.append(ckb.core.CellDep.conf_read(ckb.config.current.script.secp256k1_blake160.cell_dep))
        tx.raw.cell_deps.append(ckb.core.CellDep.conf_read(ckb.config.current.script.dao.cell_dep))
        tx.raw.header_deps.append(deposit_block_hash)
        tx.raw.header_deps.append(prepare_block_hash)
        tx.raw.outputs.append(ckb.core.CellOutput(accept_capacity, accept_script, None))
        tx.raw.outputs.append(ckb.core.CellOutput(change_capacity, change_script, None))
        tx.raw.outputs_data.append(bytearray())
        tx.raw.outputs_data.append(bytearray())
        for cell in itertools.islice(itertools.chain([idcell], self.livecell()), 256):
            cell_out_point = ckb.core.OutPoint.json_read(cell['out_point'])
            cell_capacity = int(cell['output']['capacity'], 16)
            if len(tx.witnesses) == 0:
                cell_input = ckb.core.CellInput(int(deposit_block_header['epoch'], 16) + 180 + 0x2000000000000000, cell_out_point)
            else:
                cell_input = ckb.core.CellInput(0, cell_out_point)
            sender_capacity += cell_capacity
            tx.raw.inputs.append(cell_input)
            if len(tx.witnesses) == 0:
                tx.witnesses.append(ckb.core.WitnessArgs(bytearray([0] * 65), bytearray([0] * 8), None).molecule())
            else:
                tx.witnesses.append(bytearray())
            change_capacity = sender_capacity - accept_capacity - len(tx.molecule()) - 4
            if change_capacity >= 61 * ckb.core.shannon:
                break
        assert change_capacity >= 61 * ckb.core.shannon
        tx.raw.outputs[1].capacity = change_capacity
        sign_data = bytearray()
        sign_data.extend(tx.raw.hash())
        for witness in tx.witnesses:
            sign_data.extend(len(witness).to_bytes(8, 'little'))
            sign_data.extend(witness)
        sign_data = ckb.core.hash(sign_data)
        sign = self.prikey.sign(sign_data)
        tx.witnesses[0] = ckb.core.WitnessArgs(sign, bytearray([0] * 8), None).molecule()
        return ckb.rpc.send_transaction(tx.json(), 'well_known_scripts_only')

    def dao_livecell(self):
        return ckb.rpc.get_cells_iter({
            'script': self.script.json(),
            'script_type': 'lock',
            'filter': {
                'script': ckb.core.Script(
                    ckb.config.current.script.dao.code_hash,
                    ckb.config.current.script.dao.hash_type,
                    bytearray(),
                ).json(),
            },
        })

    def dao_capacity(self):
        return int(ckb.rpc.get_cells_capacity({
            'script': self.script.json(),
            'script_type': 'lock',
            'filter': {
                'script': ckb.core.Script(
                    ckb.config.current.script.dao.code_hash,
                    ckb.config.current.script.dao.hash_type,
                    bytearray(),
                ).json(),
            }
        })['capacity'], 16)
