import ckb.config
import ckb.denomination
import ckb.core
import ckb.rpc
import itertools
import json
import math
import typing


class WalletTransactionAnalyzer:
    def __init__(self, tx: ckb.core.Transaction) -> None:
        self.tx = tx

    def analyze_mining_fee(self) -> None:
        # Make sure the transaction fee is less than 1 CKB. This is a rough check, but works well in most cases.
        sender_capacity = 0
        output_capacity = 0
        for e in self.tx.raw.inputs:
            out_point = e.previous_output
            result = ckb.rpc.get_transaction('0x' + out_point.tx_hash.hex())
            origin = ckb.core.CellOutput.json_decode(result['transaction']['outputs'][out_point.index])
            sender_capacity += origin.capacity
        for e in self.tx.raw.outputs:
            output_capacity += e.capacity
        assert sender_capacity - output_capacity <= 1 * ckb.denomination.ckbytes

    def analyze_outputs_data(self) -> None:
        assert len(self.tx.raw.outputs) == len(self.tx.raw.outputs_data)

    def analyze_outputs_lock(self) -> None:
        for e in self.tx.raw.outputs:
            if e.lock.code_hash == ckb.config.current.script.secp256k1_blake160.code_hash:
                assert e.lock.hash_type == ckb.config.current.script.secp256k1_blake160.hash_type
                assert len(e.lock.args) == 20

    def analyze_since(self) -> None:
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

    def analyze(self) -> None:
        self.analyze_mining_fee()
        self.analyze_outputs_data()
        self.analyze_outputs_lock()
        self.analyze_since()


class Wallet:
    def __init__(self, prikey: int) -> None:
        self.prikey = ckb.core.PriKey(prikey)
        self.pubkey = self.prikey.pubkey()
        self.script = ckb.core.Script(
            ckb.config.current.script.secp256k1_blake160.code_hash,
            ckb.config.current.script.secp256k1_blake160.hash_type,
            ckb.core.hash(self.pubkey.sec())[:20]
        )
        self.addr = ckb.core.address_encode(self.script)

    def __repr__(self) -> str:
        return json.dumps(self.json())

    def __eq__(self, other) -> bool:
        return all([
            self.prikey == other.prikey,
            self.pubkey == other.pubkey,
            self.script == other.script,
            self.addr == other.addr,
        ])

    def json(self) -> typing.Dict:
        return {
            'prikey': self.prikey.json(),
            'pubkey': self.pubkey.json(),
            'script': self.script.json(),
            'addr': self.addr,
        }

    def livecell(self) -> typing.Generator:
        return ckb.rpc.get_cells_iter({
            'script': self.script.json(),
            'script_type': 'lock',
            'filter': {
                'script_len_range': ['0x0', '0x1']
            }
        })

    def capacity(self) -> int:
        return int(ckb.rpc.get_cells_capacity({
            'script': self.script.json(),
            'script_type': 'lock',
            'filter': {
                'script_len_range': ['0x0', '0x1']
            }
        })['capacity'], 16)

    def transfer(self, script: ckb.core.Script, capacity: int) -> bytearray:
        assert capacity >= 61 * ckb.denomination.ckbytes
        assert self.capacity() > capacity
        sender_capacity = 0
        accept_capacity = capacity
        accept_script = script
        change_capacity = 0
        change_script = self.script
        tx = ckb.core.Transaction(ckb.core.RawTransaction(0, [], [], [], [], []), [])
        tx.raw.cell_deps.append(ckb.core.CellDep.conf_decode(ckb.config.current.script.secp256k1_blake160.cell_dep))
        tx.raw.outputs.append(ckb.core.CellOutput(accept_capacity, accept_script, None))
        tx.raw.outputs.append(ckb.core.CellOutput(change_capacity, change_script, None))
        tx.raw.outputs_data.append(bytearray())
        tx.raw.outputs_data.append(bytearray())
        tx.witnesses.append(ckb.core.WitnessArgs(bytearray(65), None, None).molecule())
        for cell in itertools.islice(self.livecell(), 256):
            cell_out_point = ckb.core.OutPoint.json_decode(cell['out_point'])
            cell_capacity = int(cell['output']['capacity'], 16)
            cell_input = ckb.core.CellInput(0, cell_out_point)
            sender_capacity += cell_capacity
            tx.raw.inputs.append(cell_input)
            change_capacity = sender_capacity - accept_capacity - len(tx.molecule()) - 4
            if change_capacity >= 61 * ckb.denomination.ckbytes:
                break
        assert change_capacity >= 61 * ckb.denomination.ckbytes
        tx.raw.outputs[1].capacity = change_capacity
        sign_data = bytearray()
        sign_data.extend(tx.raw.hash())
        sign_data.extend(len(tx.witnesses[0]).to_bytes(8, 'little'))
        sign_data.extend(tx.witnesses[0])
        sign_data = ckb.core.hash(sign_data)
        sign = self.prikey.sign(sign_data)
        tx.witnesses[0] = ckb.core.WitnessArgs(sign, None, None).molecule()
        WalletTransactionAnalyzer(tx).analyze()
        hash = ckb.rpc.send_transaction(tx.json())
        return bytearray.fromhex(hash[2:])

    def transfer_all(self, script: ckb.core.Script) -> bytearray:
        assert self.capacity() > 0
        sender_capacity = 0
        accept_capacity = 0
        accept_script = script
        tx = ckb.core.Transaction(ckb.core.RawTransaction(0, [], [], [], [], []), [])
        tx.raw.cell_deps.append(ckb.core.CellDep.conf_decode(ckb.config.current.script.secp256k1_blake160.cell_dep))
        tx.raw.outputs.append(ckb.core.CellOutput(accept_capacity, accept_script, None))
        tx.raw.outputs_data.append(bytearray())
        tx.witnesses.append(ckb.core.WitnessArgs(bytearray(65), None, None).molecule())
        for cell in itertools.islice(self.livecell(), 256):
            cell_out_point = ckb.core.OutPoint.json_decode(cell['out_point'])
            cell_capacity = int(cell['output']['capacity'], 16)
            cell_input = ckb.core.CellInput(0, cell_out_point)
            sender_capacity += cell_capacity
            tx.raw.inputs.append(cell_input)
        accept_capacity = sender_capacity - len(tx.molecule()) - 4
        tx.raw.outputs[0].capacity = accept_capacity
        sign_data = bytearray()
        sign_data.extend(tx.raw.hash())
        sign_data.extend(len(tx.witnesses[0]).to_bytes(8, 'little'))
        sign_data.extend(tx.witnesses[0])
        sign_data = ckb.core.hash(sign_data)
        sign = self.prikey.sign(sign_data)
        tx.witnesses[0] = ckb.core.WitnessArgs(sign, None, None).molecule()
        WalletTransactionAnalyzer(tx).analyze()
        hash = ckb.rpc.send_transaction(tx.json())
        return bytearray.fromhex(hash[2:])

    def script_deploy(self, script: ckb.core.Script, data: bytearray) -> bytearray:
        sender_capacity = 0
        accept_capacity = (61 + len(data)) * ckb.denomination.ckbytes
        accept_script = script
        change_capacity = 0
        change_script = self.script
        tx = ckb.core.Transaction(ckb.core.RawTransaction(0, [], [], [], [], []), [])
        tx.raw.cell_deps.append(ckb.core.CellDep.conf_decode(ckb.config.current.script.secp256k1_blake160.cell_dep))
        tx.raw.outputs.append(ckb.core.CellOutput(accept_capacity, accept_script, None))
        tx.raw.outputs.append(ckb.core.CellOutput(change_capacity, change_script, None))
        tx.raw.outputs_data.append(data)
        tx.raw.outputs_data.append(bytearray())
        tx.witnesses.append(ckb.core.WitnessArgs(bytearray(65), None, None).molecule())
        for cell in itertools.islice(self.livecell(), 256):
            cell_out_point = ckb.core.OutPoint.json_decode(cell['out_point'])
            cell_capacity = int(cell['output']['capacity'], 16)
            cell_input = ckb.core.CellInput(0, cell_out_point)
            sender_capacity += cell_capacity
            tx.raw.inputs.append(cell_input)
            change_capacity = sender_capacity - accept_capacity - len(tx.molecule()) - 4
            if change_capacity >= 61 * ckb.denomination.ckbytes:
                break
        assert change_capacity >= 61 * ckb.denomination.ckbytes
        tx.raw.outputs[1].capacity = change_capacity
        sign_data = bytearray()
        sign_data.extend(tx.raw.hash())
        sign_data.extend(len(tx.witnesses[0]).to_bytes(8, 'little'))
        sign_data.extend(tx.witnesses[0])
        sign_data = ckb.core.hash(sign_data)
        sign = self.prikey.sign(sign_data)
        tx.witnesses[0] = ckb.core.WitnessArgs(sign, None, None).molecule()
        WalletTransactionAnalyzer(tx).analyze()
        hash = ckb.rpc.send_transaction(tx.json())
        return bytearray.fromhex(hash[2:])

    def script_deploy_type_id(self, script: ckb.core.Script, data: bytearray) -> bytearray:
        sender_capacity = 0
        accept_capacity = (126 + len(data)) * ckb.denomination.ckbytes
        accept_script = script
        accept_typeid = ckb.core.Script(ckb.core.type_id_code_hash, ckb.core.type_id_hash_type, bytearray(32))
        change_capacity = 0
        change_script = self.script
        tx = ckb.core.Transaction(ckb.core.RawTransaction(0, [], [], [], [], []), [])
        tx.raw.cell_deps.append(ckb.core.CellDep.conf_decode(ckb.config.current.script.secp256k1_blake160.cell_dep))
        tx.raw.outputs.append(ckb.core.CellOutput(accept_capacity, accept_script, accept_typeid))
        tx.raw.outputs.append(ckb.core.CellOutput(change_capacity, change_script, None))
        tx.raw.outputs_data.append(data)
        tx.raw.outputs_data.append(bytearray())
        tx.witnesses.append(ckb.core.WitnessArgs(bytearray(65), None, None).molecule())
        for cell in itertools.islice(self.livecell(), 256):
            cell_out_point = ckb.core.OutPoint.json_decode(cell['out_point'])
            cell_capacity = int(cell['output']['capacity'], 16)
            cell_input = ckb.core.CellInput(0, cell_out_point)
            sender_capacity += cell_capacity
            tx.raw.inputs.append(cell_input)
            change_capacity = sender_capacity - accept_capacity - len(tx.molecule()) - 4
            if change_capacity >= 61 * ckb.denomination.ckbytes:
                break
        assert change_capacity >= 61 * ckb.denomination.ckbytes
        # https://github.com/nervosnetwork/rfcs/blob/master/rfcs/0022-transaction-structure/0022-transaction-structure.md#type-id
        tx.raw.outputs[0].type.args = ckb.core.hash(tx.raw.inputs[0].molecule() + bytearray(8))
        tx.raw.outputs[1].capacity = change_capacity
        sign_data = bytearray()
        sign_data.extend(tx.raw.hash())
        sign_data.extend(len(tx.witnesses[0]).to_bytes(8, 'little'))
        sign_data.extend(tx.witnesses[0])
        sign_data = ckb.core.hash(sign_data)
        sign = self.prikey.sign(sign_data)
        tx.witnesses[0] = ckb.core.WitnessArgs(sign, None, None).molecule()
        WalletTransactionAnalyzer(tx).analyze()
        hash = ckb.rpc.send_transaction(tx.json())
        return bytearray.fromhex(hash[2:])

    def script_update_type_id(
        self,
        script: ckb.core.Script,
        data: bytearray,
        out_point: ckb.core.OutPoint
    ) -> bytearray:
        result = ckb.rpc.get_transaction('0x' + out_point.tx_hash.hex())
        origin = ckb.core.CellOutput.json_decode(result['transaction']['outputs'][out_point.index])
        assert origin.type.code_hash == ckb.core.type_id_code_hash
        assert origin.type.hash_type == ckb.core.type_id_hash_type
        sender_capacity = origin.capacity
        accept_capacity = (126 + len(data)) * ckb.denomination.ckbytes
        accept_script = script
        accept_typeid = origin.type
        change_capacity = 0
        change_script = self.script
        tx = ckb.core.Transaction(ckb.core.RawTransaction(0, [], [], [], [], []), [])
        tx.raw.cell_deps.append(ckb.core.CellDep.conf_decode(ckb.config.current.script.secp256k1_blake160.cell_dep))
        tx.raw.inputs.append(ckb.core.CellInput(0, out_point))
        tx.raw.outputs.append(ckb.core.CellOutput(accept_capacity, accept_script, accept_typeid))
        tx.raw.outputs.append(ckb.core.CellOutput(change_capacity, change_script, None))
        tx.raw.outputs_data.append(data)
        tx.raw.outputs_data.append(bytearray())
        tx.witnesses.append(ckb.core.WitnessArgs(bytearray(65), None, None).molecule())
        for cell in itertools.islice(self.livecell(), 255):
            cell_out_point = ckb.core.OutPoint.json_decode(cell['out_point'])
            cell_capacity = int(cell['output']['capacity'], 16)
            cell_input = ckb.core.CellInput(0, cell_out_point)
            sender_capacity += cell_capacity
            tx.raw.inputs.append(cell_input)
            change_capacity = sender_capacity - accept_capacity - len(tx.molecule()) - 4
            if change_capacity >= 61 * ckb.denomination.ckbytes:
                break
        assert change_capacity >= 61 * ckb.denomination.ckbytes
        tx.raw.outputs[1].capacity = change_capacity
        sign_data = bytearray()
        sign_data.extend(tx.raw.hash())
        sign_data.extend(len(tx.witnesses[0]).to_bytes(8, 'little'))
        sign_data.extend(tx.witnesses[0])
        sign_data = ckb.core.hash(sign_data)
        sign = self.prikey.sign(sign_data)
        tx.witnesses[0] = ckb.core.WitnessArgs(sign, None, None).molecule()
        WalletTransactionAnalyzer(tx).analyze()
        hash = ckb.rpc.send_transaction(tx.json())
        return bytearray.fromhex(hash[2:])

    def dao_deposit(self, capacity: int) -> bytearray:
        # https://github.com/nervosnetwork/rfcs/blob/master/rfcs/0023-dao-deposit-withdraw/0023-dao-deposit-withdraw.md#deposit
        assert capacity >= 102 * ckb.denomination.ckbytes
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
        tx = ckb.core.Transaction(ckb.core.RawTransaction(0, [], [], [], [], []), [])
        tx.raw.cell_deps.append(ckb.core.CellDep.conf_decode(ckb.config.current.script.secp256k1_blake160.cell_dep))
        tx.raw.cell_deps.append(ckb.core.CellDep.conf_decode(ckb.config.current.script.dao.cell_dep))
        tx.raw.outputs.append(ckb.core.CellOutput(accept_capacity, accept_script, accept_typeid))
        tx.raw.outputs.append(ckb.core.CellOutput(change_capacity, change_script, None))
        tx.raw.outputs_data.append(bytearray(8))
        tx.raw.outputs_data.append(bytearray())
        tx.witnesses.append(ckb.core.WitnessArgs(bytearray(65), None, None).molecule())
        for cell in itertools.islice(self.livecell(), 256):
            cell_out_point = ckb.core.OutPoint.json_decode(cell['out_point'])
            cell_capacity = int(cell['output']['capacity'], 16)
            cell_input = ckb.core.CellInput(0, cell_out_point)
            sender_capacity += cell_capacity
            tx.raw.inputs.append(cell_input)
            change_capacity = sender_capacity - accept_capacity - len(tx.molecule()) - 4
            if change_capacity >= 61 * ckb.denomination.ckbytes:
                break
        assert change_capacity >= 61 * ckb.denomination.ckbytes
        tx.raw.outputs[1].capacity = change_capacity
        sign_data = bytearray()
        sign_data.extend(tx.raw.hash())
        sign_data.extend(len(tx.witnesses[0]).to_bytes(8, 'little'))
        sign_data.extend(tx.witnesses[0])
        sign_data = ckb.core.hash(sign_data)
        sign = self.prikey.sign(sign_data)
        tx.witnesses[0] = ckb.core.WitnessArgs(sign, None, None).molecule()
        WalletTransactionAnalyzer(tx).analyze()
        hash = ckb.rpc.send_transaction(tx.json())
        return bytearray.fromhex(hash[2:])

    def dao_prepare(self, out_point: ckb.core.OutPoint) -> bytearray:
        # https://github.com/nervosnetwork/rfcs/blob/master/rfcs/0023-dao-deposit-withdraw/0023-dao-deposit-withdraw.md#withdraw-phase-1
        result = ckb.rpc.get_transaction('0x' + out_point.tx_hash.hex())
        number = int(ckb.rpc.get_header(result['tx_status']['block_hash'])['number'], 16)
        origin = ckb.core.CellOutput.json_decode(result['transaction']['outputs'][out_point.index])
        assert origin.type.code_hash == ckb.config.current.script.dao.code_hash
        assert origin.type.hash_type == ckb.config.current.script.dao.hash_type
        assert origin.type.args == bytearray()
        sender_capacity = origin.capacity
        accept_capacity = origin.capacity
        accept_script = origin.lock
        accept_typeid = origin.type
        change_capacity = 0
        change_script = self.script
        tx = ckb.core.Transaction(ckb.core.RawTransaction(0, [], [], [], [], []), [])
        tx.raw.cell_deps.append(ckb.core.CellDep.conf_decode(ckb.config.current.script.secp256k1_blake160.cell_dep))
        tx.raw.cell_deps.append(ckb.core.CellDep.conf_decode(ckb.config.current.script.dao.cell_dep))
        tx.raw.header_deps.append(bytearray.fromhex(result['tx_status']['block_hash'][2:]))
        tx.raw.inputs.append(ckb.core.CellInput(0, out_point))
        tx.raw.outputs.append(ckb.core.CellOutput(accept_capacity, accept_script, accept_typeid))
        tx.raw.outputs.append(ckb.core.CellOutput(change_capacity, change_script, None))
        tx.raw.outputs_data.append(number.to_bytes(8, 'little'))
        tx.raw.outputs_data.append(bytearray())
        tx.witnesses.append(ckb.core.WitnessArgs(bytearray(65), None, None).molecule())
        for cell in itertools.islice(self.livecell(), 255):
            cell_out_point = ckb.core.OutPoint.json_decode(cell['out_point'])
            cell_capacity = int(cell['output']['capacity'], 16)
            cell_input = ckb.core.CellInput(0, cell_out_point)
            sender_capacity += cell_capacity
            tx.raw.inputs.append(cell_input)
            change_capacity = sender_capacity - accept_capacity - len(tx.molecule()) - 4
            if change_capacity >= 61 * ckb.denomination.ckbytes:
                break
        assert change_capacity >= 61 * ckb.denomination.ckbytes
        tx.raw.outputs[1].capacity = change_capacity
        sign_data = bytearray()
        sign_data.extend(tx.raw.hash())
        sign_data.extend(len(tx.witnesses[0]).to_bytes(8, 'little'))
        sign_data.extend(tx.witnesses[0])
        sign_data = ckb.core.hash(sign_data)
        sign = self.prikey.sign(sign_data)
        tx.witnesses[0] = ckb.core.WitnessArgs(sign, None, None).molecule()
        WalletTransactionAnalyzer(tx).analyze()
        hash = ckb.rpc.send_transaction(tx.json())
        return bytearray.fromhex(hash[2:])

    def dao_extract(self, out_point: ckb.core.OutPoint) -> bytearray:
        # https://github.com/nervosnetwork/rfcs/blob/master/rfcs/0023-dao-deposit-withdraw/0023-dao-deposit-withdraw.md#withdraw-phase-2
        result = ckb.rpc.get_transaction('0x' + out_point.tx_hash.hex())
        origin = ckb.core.CellOutput.json_decode(result['transaction']['outputs'][out_point.index])
        assert origin.type.code_hash == ckb.config.current.script.dao.code_hash
        assert origin.type.hash_type == ckb.config.current.script.dao.hash_type
        assert origin.type.args == bytearray()
        deposit_block_number_byte = bytearray.fromhex(result['transaction']['outputs_data'][out_point.index][2:])
        deposit_block_number = int.from_bytes(deposit_block_number_byte, 'little')
        deposit_block_header = ckb.core.Header.json_decode(ckb.rpc.get_header_by_number(hex(deposit_block_number)))
        deposit_block_hash = deposit_block_header.hash()
        deposit_block_epoch = ckb.core.epoch_decode(deposit_block_header.raw.epoch)
        deposit_block_epoch_float = deposit_block_epoch[0] + deposit_block_epoch[1] / deposit_block_epoch[2]
        deposit_dao_ar = ckb.core.dao_decode(deposit_block_header.raw.dao)[1]
        prepare_block_hash = bytearray.fromhex(result['tx_status']['block_hash'][2:])
        prepare_block_header = ckb.core.Header.json_decode(ckb.rpc.get_header('0x' + prepare_block_hash.hex()))
        prepare_block_epoch = ckb.core.epoch_decode(prepare_block_header.raw.epoch)
        prepare_block_epoch_float = prepare_block_epoch[0] + prepare_block_epoch[1] / prepare_block_epoch[2]
        prepare_dao_ar = ckb.core.dao_decode(prepare_block_header.raw.dao)[1]
        extract_since_delay = math.ceil((prepare_block_epoch_float - deposit_block_epoch_float) / 180) * 180
        extract_since_epoch = ckb.core.epoch_encode(
            deposit_block_epoch[0] + extract_since_delay,
            deposit_block_epoch[1],
            deposit_block_epoch[2],
        )
        extract_since = 0x2000000000000000 + extract_since_epoch
        occupy_capacity = 102 * ckb.denomination.ckbytes
        sender_capacity = (origin.capacity - occupy_capacity) * prepare_dao_ar // deposit_dao_ar + occupy_capacity
        accept_capacity = 0
        accept_script = self.script
        tx = ckb.core.Transaction(ckb.core.RawTransaction(0, [], [], [], [], []), [])
        tx.raw.cell_deps.append(ckb.core.CellDep.conf_decode(ckb.config.current.script.secp256k1_blake160.cell_dep))
        tx.raw.cell_deps.append(ckb.core.CellDep.conf_decode(ckb.config.current.script.dao.cell_dep))
        tx.raw.header_deps.append(deposit_block_hash)
        tx.raw.header_deps.append(prepare_block_hash)
        tx.raw.inputs.append(ckb.core.CellInput(extract_since, out_point))
        tx.raw.outputs.append(ckb.core.CellOutput(accept_capacity, accept_script, None))
        tx.raw.outputs_data.append(bytearray())
        tx.witnesses.append(ckb.core.WitnessArgs(bytearray(65), bytearray(8), None).molecule())
        accept_capacity = sender_capacity - len(tx.molecule()) - 4
        tx.raw.outputs[0].capacity = accept_capacity
        sign_data = bytearray()
        sign_data.extend(tx.raw.hash())
        sign_data.extend(len(tx.witnesses[0]).to_bytes(8, 'little'))
        sign_data.extend(tx.witnesses[0])
        sign_data = ckb.core.hash(sign_data)
        sign = self.prikey.sign(sign_data)
        tx.witnesses[0] = ckb.core.WitnessArgs(sign, bytearray(8), None).molecule()
        WalletTransactionAnalyzer(tx).analyze()
        hash = ckb.rpc.send_transaction(tx.json())
        return bytearray.fromhex(hash[2:])

    def dao_livecell(self) -> typing.Generator:
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

    def dao_capacity(self) -> int:
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
