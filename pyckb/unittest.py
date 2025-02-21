import json
import pyckb.core
import subprocess
import typing


class Cell:
    # Define a class to represent a ckb cell, which is a basic unit of data storage in the ckb blockchain.

    def __init__(self, out_point: pyckb.core.OutPoint, cell_output: pyckb.core.CellOutput, data: bytearray) -> None:
        self.out_point = out_point
        self.cell_ouput = cell_output
        self.data = data


class Resource:
    # Define a class to manage resources, primarily cells.

    def __init__(self) -> None:
        self.cell: typing.Dict[pyckb.core.OutPoint, Cell] = {}
        self.cell_outpoint_hash = bytearray(32)
        self.cell_outpoint_incr = 0

    def create_cell(
        self,
        capacity: int,
        lock: pyckb.core.Script,
        type: pyckb.core.Script | None,
        data: bytearray,
    ) -> Cell:
        # Create a new cell with specified parameters and store it in the resource.
        cell_out_point = pyckb.core.OutPoint(self.cell_outpoint_hash, self.cell_outpoint_incr)
        cell_output = pyckb.core.CellOutput(capacity, lock, type)
        cell_meta = Cell(cell_out_point, cell_output, data)
        self.cell[cell_out_point] = cell_meta
        self.cell_outpoint_incr += 1
        return cell_meta

    def create_cell_dep(self, cell: Cell, dep_type: int) -> pyckb.core.CellDep:
        # Create a cell dependency referencing an existing cell.
        return pyckb.core.CellDep(cell.out_point, dep_type)

    def create_cell_input(self, cell: Cell) -> pyckb.core.CellInput:
        # Create an input referencing an existing cell.
        return pyckb.core.CellInput(0, cell.out_point)

    def create_cell_output(
        self,
        capacity: int,
        lock: pyckb.core.Script,
        type: pyckb.core.Script | None,
    ) -> pyckb.core.CellOutput:
        # Create a cell output with specified parameters.
        return pyckb.core.CellOutput(capacity, lock, type)

    def create_script_by_data(self, cell: Cell, args: bytearray) -> pyckb.core.Script:
        # Create a script using the hash of a cell's data as the code hash.
        return pyckb.core.Script(pyckb.core.hash(cell.data), pyckb.core.script_hash_type_data2, args)

    def create_script_by_type(self, cell: Cell, args: bytearray) -> pyckb.core.Script:
        # Create a script using the hash of a cell's type script as the code hash.
        return pyckb.core.Script(cell.cell_ouput.type.hash(), pyckb.core.script_hash_type_type, args)

    def create_script_in_vain(self) -> pyckb.core.Script:
        # Create a dummy script with zeroed-out code hash and no arguments.
        return pyckb.core.Script(bytearray(32), pyckb.core.script_hash_type_data2, bytearray())

    def create_type_id(self) -> pyckb.core.Script:
        # Create a type id script, commonly used in ckb for unique identification.
        args = bytearray(self.cell_outpoint_incr.to_bytes(32))
        return pyckb.core.Script(pyckb.core.type_id_code_hash, pyckb.core.type_id_hash_type, args)


class Verifier:
    # Define a class to verify transactions using the ckb-debugger tool.

    def __init__(self, resource: Resource, tx: pyckb.core.Transaction) -> None:
        # Path/command for the CKB debugger tool.
        self.debugger = 'ckb-debugger'
        self.resource = resource
        self.tx = tx

    def json(self) -> typing.Dict:
        # Generate a json representation of the transaction with mock data for debugging.
        mock = {'cell_deps': [], 'header_deps': [], 'inputs': []}
        # Add cell dependencies to the mock info.
        deps = self.tx.raw.cell_deps.copy()
        for e in [e for e in self.tx.raw.cell_deps if e.dep_type == 1]:
            cell = self.resource.cell[e.out_point]
            cout = [pyckb.core.OutPoint.molecule_decode(e) for e in pyckb.molecule.decode_fixvec(cell.data)]
            cdep = [pyckb.core.CellDep(e, 0) for e in cout]
            deps.extend(cdep)
        for e in deps:
            cell = self.resource.cell[e.out_point]
            mock['cell_deps'].append({
                'cell_dep': e.json(),
                'output': cell.cell_ouput.json(),
                'data': f'0x{cell.data.hex()}',
            })
        # Add inputs to the mock info.
        for e in self.tx.raw.inputs:
            cell = self.resource.cell[e.previous_output]
            mock['inputs'].append({
                'input': e.json(),
                'output': cell.cell_ouput.json(),
                'data': f'0x{cell.data.hex()}',
            })
        return {'mock_info': mock, 'tx': self.tx.json()}

    def verify_success(self) -> None:
        # Verify that the transaction succeeds (all scripts return 0x00).
        assert len([e for e in self.verify() if e.returncode != 0x00]) == 0

    def verify_failure(self) -> None:
        # Verify that the transaction fails (at least one script returns 0xfe).
        assert len([e for e in self.verify() if e.returncode == 0xfe]) != 0

    def verify(self) -> typing.List[subprocess.CompletedProcess[bytes]]:
        # Run the ckb-debugger on each script in the transaction and collect results.
        txfile = json.dumps(self.json()).encode()
        result = []
        for i, e in enumerate(self.tx.raw.inputs):
            cell = self.resource.cell[e.previous_output]
            cmds = f'{self.debugger} --tx-file - --script input.{i}.lock'
            rets = subprocess.run(cmds, capture_output=True, input=txfile, shell=True)
            result.append(rets)
            if not cell.cell_ouput.type:
                continue
            cmds = f'{self.debugger} --tx-file - --script input.{i}.type'
            rets = subprocess.run(cmds, capture_output=True, input=txfile, shell=True)
            result.append(rets)
        for i, e in enumerate(self.tx.raw.outputs):
            if not e.type:
                continue
            cmds = f'{self.debugger} --tx-file - --script output.{i}.type'
            rets = subprocess.run(cmds, capture_output=True, input=txfile, shell=True)
            result.append(rets)
        return result


# Bytearray representing a riscv elf binary that always succeeds (returns 0).
script_always_success = bytearray([
    0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x02, 0x00, 0xf3, 0x00, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x98, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x05, 0x00, 0x00, 0x00, 0x40, 0x00, 0x38, 0x00, 0x01, 0x00, 0x40, 0x00, 0x03, 0x00, 0x02, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x82, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x82, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x45, 0x93, 0x08, 0xd0, 0x05, 0x73, 0x00,
    0x00, 0x00, 0x00, 0x2e, 0x73, 0x68, 0x73, 0x74, 0x72, 0x74, 0x61, 0x62, 0x00, 0x2e, 0x74, 0x65,
    0x78, 0x74, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x78, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x78, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x82, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
])

# Bytearray representing a riscv elf binary that always fails (returns -1).
script_always_failure = bytearray([
    0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x02, 0x00, 0xf3, 0x00, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xd0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x40, 0x00, 0x38, 0x00, 0x01, 0x00, 0x40, 0x00, 0x04, 0x00, 0x03, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x84, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x13, 0x05, 0xf0, 0x0f, 0x93, 0x08, 0xd0, 0x05,
    0x73, 0x00, 0x00, 0x00, 0x41, 0x28, 0x00, 0x00, 0x00, 0x72, 0x69, 0x73, 0x63, 0x76, 0x00, 0x01,
    0x1e, 0x00, 0x00, 0x00, 0x05, 0x72, 0x76, 0x36, 0x34, 0x69, 0x32, 0x70, 0x30, 0x5f, 0x6d, 0x32,
    0x70, 0x30, 0x5f, 0x61, 0x32, 0x70, 0x30, 0x5f, 0x63, 0x32, 0x70, 0x30, 0x00, 0x00, 0x2e, 0x73,
    0x68, 0x73, 0x74, 0x72, 0x74, 0x61, 0x62, 0x00, 0x2e, 0x74, 0x65, 0x78, 0x74, 0x00, 0x2e, 0x72,
    0x69, 0x73, 0x63, 0x76, 0x2e, 0x61, 0x74, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x65, 0x73, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x0b, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x78, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x78, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x11, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x70, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x29, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xad, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x23, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
])
