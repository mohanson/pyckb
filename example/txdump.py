import argparse
import json
import pyckb

# Dump full transaction data for [ckb-debugger](https://github.com/nervosnetwork/ckb-standalone-debugger) to use.

parser = argparse.ArgumentParser()
parser.add_argument('--file', type=str, help='transaction file')
parser.add_argument('--hash', type=str, help='transaction hash')
parser.add_argument('--net', type=str, choices=['develop', 'mainnet', 'testnet'], default='develop')
args = parser.parse_args()

assert args.file or args.hash

if args.net == 'develop':
    pyckb.config.upgrade('http://127.0.0.1:8114')
    pyckb.config.current = pyckb.config.develop
if args.net == 'mainnet':
    pyckb.config.current = pyckb.config.mainnet
if args.net == 'testnet':
    pyckb.config.current = pyckb.config.testnet

tx_json = {}
if args.file:
    tx_json = json.load(open(args.file))
if args.hash:
    tx_json = pyckb.rpc.get_transaction(args.hash)['transaction']
tx = pyckb.core.Transaction.rpc_decode(tx_json)

mock = {'cell_deps': [], 'header_deps': [], 'inputs': []}
deps = tx.raw.cell_deps.copy()
for e in [e for e in tx.raw.cell_deps if e.dep_type == 1]:
    origin = pyckb.rpc.get_transaction(f'0x{e.out_point.tx_hash.hex()}')
    origin = pyckb.core.Transaction.rpc_decode(origin['transaction'])
    data = origin.raw.outputs_data[e.out_point.index]
    outs = pyckb.molecule.Slice(pyckb.molecule.Custom(pyckb.core.OutPoint.molecule_size())).decode(data)
    outs = [pyckb.core.OutPoint.molecule_decode(e) for e in outs]
    deps.extend([pyckb.core.CellDep(e, 0) for e in outs])
for e in deps:
    origin = pyckb.rpc.get_transaction(f'0x{e.out_point.tx_hash.hex()}')
    header = origin['tx_status']['block_hash']
    origin = pyckb.core.Transaction.rpc_decode(origin['transaction'])
    output = origin.raw.outputs[e.out_point.index]
    data = origin.raw.outputs_data[e.out_point.index]
    mock['cell_deps'].append({
        'cell_dep': e.rpc(),
        'header': header,
        'data': f'0x{data.hex()}',
        'output': output.rpc(),
    })
for h in tx.raw.header_deps:
    header = pyckb.rpc.get_header(f'0x{h.hex()}')
    mock['header_deps'].append(header)
for e in tx.raw.inputs:
    origin = pyckb.rpc.get_transaction(f'0x{e.previous_output.tx_hash.hex()}')
    header = origin['tx_status']['block_hash']
    origin = pyckb.core.Transaction.rpc_decode(origin['transaction'])
    output = origin.raw.outputs[e.previous_output.index]
    data = origin.raw.outputs_data[e.previous_output.index]
    mock['inputs'].append({
        'input': e.rpc(),
        'output': output.rpc(),
        'data': f'0x{data.hex()}',
        'header': header,
    })

print(json.dumps({'mock_info': mock, 'tx': tx.rpc()}, indent=4))
