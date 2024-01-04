import ckb.config
import ckb.core
import ckb.rpc
import itertools
import json
import math


class WalletTransactionAnalyzer:
    def __init__(self, tx: ckb.core.Transaction):
        self.tx = tx

    def analyze_mining_fee(self):
        # Make sure the transaction fee is less than 1 CKB. This is a rough check, but works well in most cases.
        sender_capacity = 0
        output_capacity = 0
        for e in self.tx.raw.inputs:
            out_point = e.previous_output
            result = ckb.rpc.get_transaction('0x' + out_point.tx_hash.hex())
            origin = ckb.core.CellOutput.json_read(result['transaction']['outputs'][out_point.index])
            sender_capacity += origin.capacity
        for e in self.tx.raw.outputs:
            output_capacity += e.capacity
        assert sender_capacity - output_capacity <= 1 * ckb.core.shannon

    def analyze_since(self):
        # Transaction since precondition
        # See https://github.com/nervosnetwork/rfcs/blob/master/rfcs/0017-tx-valid-since/0017-tx-valid-since.md
        for e in self.tx.raw.inputs:
            if e.since == 0:
                continue
            if e.since >> 56 == 0x00:
                pass
            if e.since >> 56 == 0x20:
                current_epoch = ckb.core.epoch_decode(int(ckb.rpc.get_tip_header()['epoch'], 16))
                request_epoch = ckb.core.epoch_decode(e.since & 0xffffffffffffff)
                if current_epoch[0] == request_epoch[0]:
                    assert current_epoch[1] >= request_epoch[1]
                else:
                    assert current_epoch[0] >= request_epoch[0]
            if e.since >> 56 == 0x60:
                pass
            if e.since >> 56 == 0x80:
                pass
            if e.since >> 56 == 0xa0:
                pass
            if e.since >> 56 == 0xe0:
                pass

    def analyze(self):
        self.analyze_mining_fee()
        self.analyze_since()


class Wallet:
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
        tx.witnesses.append(ckb.core.WitnessArgs(bytearray([0] * 65), None, None).molecule())
        for cell in itertools.islice(self.livecell(), 256):
            cell_out_point = ckb.core.OutPoint.json_read(cell['out_point'])
            cell_capacity = int(cell['output']['capacity'], 16)
            cell_input = ckb.core.CellInput(0, cell_out_point)
            sender_capacity += cell_capacity
            tx.raw.inputs.append(cell_input)
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
        WalletTransactionAnalyzer(tx).analyze()
        hash = ckb.rpc.send_transaction(tx.json())
        return bytearray.fromhex(hash[2:])

    def transfer_all(self, script: ckb.core.Script):
        assert self.capacity() > 0
        sender_capacity = 0
        accept_capacity = 0
        accept_script = script
        tx = ckb.core.Transaction(ckb.core.TransactionRaw(0, [], [], [], [], []), [])
        tx.raw.cell_deps.append(ckb.core.CellDep.conf_read(ckb.config.current.script.secp256k1_blake160.cell_dep))
        tx.raw.outputs.append(ckb.core.CellOutput(accept_capacity, accept_script, None))
        tx.raw.outputs_data.append(bytearray())
        tx.witnesses.append(ckb.core.WitnessArgs(bytearray([0] * 65), None, None).molecule())
        for cell in itertools.islice(self.livecell(), 256):
            cell_out_point = ckb.core.OutPoint.json_read(cell['out_point'])
            cell_capacity = int(cell['output']['capacity'], 16)
            cell_input = ckb.core.CellInput(0, cell_out_point)
            sender_capacity += cell_capacity
            tx.raw.inputs.append(cell_input)
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
        WalletTransactionAnalyzer(tx).analyze()
        hash = ckb.rpc.send_transaction(tx.json())
        return bytearray.fromhex(hash[2:])

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
        tx.witnesses.append(ckb.core.WitnessArgs(bytearray([0] * 65), None, None).molecule())
        for cell in itertools.islice(self.livecell(), 256):
            cell_out_point = ckb.core.OutPoint.json_read(cell['out_point'])
            cell_capacity = int(cell['output']['capacity'], 16)
            cell_input = ckb.core.CellInput(0, cell_out_point)
            sender_capacity += cell_capacity
            tx.raw.inputs.append(cell_input)
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
        WalletTransactionAnalyzer(tx).analyze()
        hash = ckb.rpc.send_transaction(tx.json())
        return bytearray.fromhex(hash[2:])

    def script_deploy_type_id(self, script: ckb.core.Script, data: bytearray):
        sender_capacity = 0
        accept_capacity = (126 + len(data)) * ckb.core.shannon
        accept_script = script
        accept_typeid = ckb.core.Script(ckb.core.type_id_code_hash, ckb.core.type_id_hash_type, bytearray([0] * 32))
        change_capacity = 0
        change_script = self.script
        tx = ckb.core.Transaction(ckb.core.TransactionRaw(0, [], [], [], [], []), [])
        tx.raw.cell_deps.append(ckb.core.CellDep.conf_read(ckb.config.current.script.secp256k1_blake160.cell_dep))
        tx.raw.outputs.append(ckb.core.CellOutput(accept_capacity, accept_script, accept_typeid))
        tx.raw.outputs.append(ckb.core.CellOutput(change_capacity, change_script, None))
        tx.raw.outputs_data.append(data)
        tx.raw.outputs_data.append(bytearray())
        tx.witnesses.append(ckb.core.WitnessArgs(bytearray([0] * 65), None, None).molecule())
        for cell in itertools.islice(self.livecell(), 256):
            cell_out_point = ckb.core.OutPoint.json_read(cell['out_point'])
            cell_capacity = int(cell['output']['capacity'], 16)
            cell_input = ckb.core.CellInput(0, cell_out_point)
            sender_capacity += cell_capacity
            tx.raw.inputs.append(cell_input)
            change_capacity = sender_capacity - accept_capacity - len(tx.molecule()) - 4
            if change_capacity >= 61 * ckb.core.shannon:
                break
        assert change_capacity >= 61 * ckb.core.shannon
        # https://github.com/nervosnetwork/rfcs/blob/master/rfcs/0022-transaction-structure/0022-transaction-structure.md#type-id
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
        WalletTransactionAnalyzer(tx).analyze()
        hash = ckb.rpc.send_transaction(tx.json())
        return bytearray.fromhex(hash[2:])

    def script_update_type_id(self, script: ckb.core.Script, data: bytearray, out_point: ckb.core.OutPoint):
        result = ckb.rpc.get_transaction('0x' + out_point.tx_hash.hex())
        origin = ckb.core.CellOutput.json_read(result['transaction']['outputs'][out_point.index])
        assert origin.type.code_hash == ckb.core.type_id_code_hash
        assert origin.type.hash_type == ckb.core.type_id_hash_type
        sender_capacity = origin.capacity
        accept_capacity = (126 + len(data)) * ckb.core.shannon
        accept_script = script
        accept_typeid = origin.type
        change_capacity = 0
        change_script = self.script
        tx = ckb.core.Transaction(ckb.core.TransactionRaw(0, [], [], [], [], []), [])
        tx.raw.cell_deps.append(ckb.core.CellDep.conf_read(ckb.config.current.script.secp256k1_blake160.cell_dep))
        tx.raw.inputs.append(ckb.core.CellInput(0, out_point))
        tx.raw.outputs.append(ckb.core.CellOutput(accept_capacity, accept_script, accept_typeid))
        tx.raw.outputs.append(ckb.core.CellOutput(change_capacity, change_script, None))
        tx.raw.outputs_data.append(data)
        tx.raw.outputs_data.append(bytearray())
        tx.witnesses.append(ckb.core.WitnessArgs(bytearray([0] * 65), None, None).molecule())
        for cell in itertools.islice(self.livecell(), 255):
            cell_out_point = ckb.core.OutPoint.json_read(cell['out_point'])
            cell_capacity = int(cell['output']['capacity'], 16)
            cell_input = ckb.core.CellInput(0, cell_out_point)
            sender_capacity += cell_capacity
            tx.raw.inputs.append(cell_input)
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
        WalletTransactionAnalyzer(tx).analyze()
        hash = ckb.rpc.send_transaction(tx.json(), 'passthrough')
        return bytearray.fromhex(hash[2:])

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
        tx.witnesses.append(ckb.core.WitnessArgs(bytearray([0] * 65), None, None).molecule())
        for cell in itertools.islice(self.livecell(), 256):
            cell_out_point = ckb.core.OutPoint.json_read(cell['out_point'])
            cell_capacity = int(cell['output']['capacity'], 16)
            cell_input = ckb.core.CellInput(0, cell_out_point)
            sender_capacity += cell_capacity
            tx.raw.inputs.append(cell_input)
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
        WalletTransactionAnalyzer(tx).analyze()
        hash = ckb.rpc.send_transaction(tx.json())
        return bytearray.fromhex(hash[2:])

    def dao_prepare(self, out_point: ckb.core.OutPoint):
        # https://github.com/nervosnetwork/rfcs/blob/master/rfcs/0023-dao-deposit-withdraw/0023-dao-deposit-withdraw.md#withdraw-phase-1
        result = ckb.rpc.get_transaction('0x' + out_point.tx_hash.hex())
        number = int(ckb.rpc.get_header(result['tx_status']['block_hash'])['number'], 16)
        origin = ckb.core.CellOutput.json_read(result['transaction']['outputs'][out_point.index])
        assert origin.type.code_hash == ckb.config.current.script.dao.code_hash
        assert origin.type.hash_type == ckb.config.current.script.dao.hash_type
        assert origin.type.args == bytearray()
        sender_capacity = origin.capacity
        accept_capacity = origin.capacity
        accept_script = origin.lock
        accept_typeid = origin.type
        change_capacity = 0
        change_script = self.script
        tx = ckb.core.Transaction(ckb.core.TransactionRaw(0, [], [], [], [], []), [])
        tx.raw.cell_deps.append(ckb.core.CellDep.conf_read(ckb.config.current.script.secp256k1_blake160.cell_dep))
        tx.raw.cell_deps.append(ckb.core.CellDep.conf_read(ckb.config.current.script.dao.cell_dep))
        tx.raw.header_deps.append(bytearray.fromhex(result['tx_status']['block_hash'][2:]))
        tx.raw.inputs.append(ckb.core.CellInput(0, out_point))
        tx.raw.outputs.append(ckb.core.CellOutput(accept_capacity, accept_script, accept_typeid))
        tx.raw.outputs.append(ckb.core.CellOutput(change_capacity, change_script, None))
        tx.raw.outputs_data.append(number.to_bytes(8, 'little'))
        tx.raw.outputs_data.append(bytearray())
        tx.witnesses.append(ckb.core.WitnessArgs(bytearray([0] * 65), None, None).molecule())
        for cell in itertools.islice(self.livecell(), 255):
            cell_out_point = ckb.core.OutPoint.json_read(cell['out_point'])
            cell_capacity = int(cell['output']['capacity'], 16)
            cell_input = ckb.core.CellInput(0, cell_out_point)
            sender_capacity += cell_capacity
            tx.raw.inputs.append(cell_input)
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
        WalletTransactionAnalyzer(tx).analyze()
        hash = ckb.rpc.send_transaction(tx.json())
        return bytearray.fromhex(hash[2:])

    def dao_extract(self, out_point: ckb.core.OutPoint):
        # https://github.com/nervosnetwork/rfcs/blob/master/rfcs/0023-dao-deposit-withdraw/0023-dao-deposit-withdraw.md#withdraw-phase-2
        result = ckb.rpc.get_transaction('0x' + out_point.tx_hash.hex())
        origin = ckb.core.CellOutput.json_read(result['transaction']['outputs'][out_point.index])
        assert origin.type.code_hash == ckb.config.current.script.dao.code_hash
        assert origin.type.hash_type == ckb.config.current.script.dao.hash_type
        assert origin.type.args == bytearray()
        deposit_block_number_byte = bytearray.fromhex(result['transaction']['outputs_data'][out_point.index][2:])
        deposit_block_number = int.from_bytes(deposit_block_number_byte, 'little')
        deposit_block_header = ckb.rpc.get_header_by_number(hex(deposit_block_number))
        deposit_block_hash = bytearray.fromhex(deposit_block_header['hash'][2:])
        deposit_block_epoch = ckb.core.epoch_decode(int(deposit_block_header['epoch'], 16))
        deposit_block_epoch_float = deposit_block_epoch[0] + deposit_block_epoch[1] / deposit_block_epoch[2]
        deposit_dao_ar = int.from_bytes(bytearray.fromhex(deposit_block_header['dao'][2:])[8:16], 'little')
        prepare_block_hash = bytearray.fromhex(result['tx_status']['block_hash'][2:])
        prepare_block_header = ckb.rpc.get_header('0x' + prepare_block_hash.hex())
        prepare_block_epoch = ckb.core.epoch_decode(int(prepare_block_header['epoch'], 16))
        prepare_block_epoch_float = prepare_block_epoch[0] + prepare_block_epoch[1] / prepare_block_epoch[2]
        prepare_dao_ar = int.from_bytes(bytearray.fromhex(prepare_block_header['dao'][2:])[8:16], 'little')
        extract_since_delay = math.ceil((prepare_block_epoch_float - deposit_block_epoch_float) / 180) * 180
        extract_since_epoch = ckb.core.epoch_encode(
            deposit_block_epoch[0] + extract_since_delay,
            deposit_block_epoch[1],
            deposit_block_epoch[2],
        )
        extract_since = 0x2000000000000000 + extract_since_epoch
        occupy_capacity = 102 * ckb.core.shannon
        sender_capacity = (origin.capacity - occupy_capacity) * prepare_dao_ar // deposit_dao_ar + occupy_capacity
        accept_capacity = 0
        accept_script = self.script
        tx = ckb.core.Transaction(ckb.core.TransactionRaw(0, [], [], [], [], []), [])
        tx.raw.cell_deps.append(ckb.core.CellDep.conf_read(ckb.config.current.script.secp256k1_blake160.cell_dep))
        tx.raw.cell_deps.append(ckb.core.CellDep.conf_read(ckb.config.current.script.dao.cell_dep))
        tx.raw.header_deps.append(deposit_block_hash)
        tx.raw.header_deps.append(prepare_block_hash)
        tx.raw.inputs.append(ckb.core.CellInput(extract_since, out_point))
        tx.raw.outputs.append(ckb.core.CellOutput(accept_capacity, accept_script, None))
        tx.raw.outputs_data.append(bytearray())
        tx.witnesses.append(ckb.core.WitnessArgs(bytearray([0] * 65), bytearray([0] * 8), None).molecule())
        accept_capacity = sender_capacity - len(tx.molecule()) - 4
        tx.raw.outputs[0].capacity = accept_capacity
        sign_data = bytearray()
        sign_data.extend(tx.raw.hash())
        for witness in tx.witnesses:
            sign_data.extend(len(witness).to_bytes(8, 'little'))
            sign_data.extend(witness)
        sign_data = ckb.core.hash(sign_data)
        sign = self.prikey.sign(sign_data)
        tx.witnesses[0] = ckb.core.WitnessArgs(sign, bytearray([0] * 8), None).molecule()
        WalletTransactionAnalyzer(tx).analyze()
        hash = ckb.rpc.send_transaction(tx.json())
        return bytearray.fromhex(hash[2:])

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
