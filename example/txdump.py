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

if args.file:
    tx_json = json.load(open(args.file))
if args.hash:
    tx_json = pyckb.rpc.get_transaction(args.hash)['transaction']
tx = pyckb.core.Transaction.json_decode(tx_json)

tx_mock = {
    'mock_info': {
        'inputs': [],
        'cell_deps': [],
        'header_deps': []
    },
    'tx': tx.json(),
}

for i in tx.raw.inputs:
    i_tx_rpc = pyckb.rpc.get_transaction(f'0x{i.previous_output.tx_hash.hex()}')
    i_tx = pyckb.core.Transaction.json_decode(i_tx_rpc['transaction'])
    i_output = i_tx.raw.outputs[i.previous_output.index]
    i_data = i_tx.raw.outputs_data[i.previous_output.index]
    i_header = i_tx_rpc['tx_status']['block_hash']
    tx_mock['mock_info']['inputs'].append({
        'input': i.json(),
        'output': i_output.json(),
        'data': f'0x{i_data.hex()}',
        'header': i_header,
    })
for c in tx.raw.cell_deps:
    c_tx_rpc = pyckb.rpc.get_transaction(f'0x{c.out_point.tx_hash.hex()}')
    c_tx = pyckb.core.Transaction.json_decode(c_tx_rpc['transaction'])
    c_output = c_tx.raw.outputs[c.out_point.index]
    c_data = c_tx.raw.outputs_data[c.out_point.index]
    c_header = c_tx_rpc['tx_status']['block_hash']
    tx_mock['mock_info']['cell_deps'].append({
        'cell_dep': c.json(),
        'output': c_output.json(),
        'data': f'0x{c_data.hex()}',
        'header': c_header,
    })
for i in range(len(tx.raw.cell_deps)):
    c = tx.raw.cell_deps[i]
    if c.dep_type != 1:
        continue
    c_data = bytearray.fromhex(tx_mock['mock_info']['cell_deps'][i]['data'][2:])
    for e in pyckb.molecule.decode_fixvec(c_data):
        d = pyckb.core.OutPoint.molecule_decode(e)
        d_tx_rpc = pyckb.rpc.get_transaction(f'0x{d.tx_hash.hex()}')
        d_tx = pyckb.core.Transaction.json_decode(d_tx_rpc['transaction'])
        d_output = d_tx.raw.outputs[d.index]
        d_data = d_tx.raw.outputs_data[d.index]
        d_header = d_tx_rpc['tx_status']['block_hash']
        tx_mock['mock_info']['cell_deps'].append({
            'cell_dep': pyckb.core.CellDep(d, 0).json(),
            'output': d_output.json(),
            'data': f'0x{d_data.hex()}',
            'header': d_header,
        })
for h in tx.raw.header_deps:
    h_rpc = pyckb.rpc.get_header(f'0x{h.hex()}')
    tx_mock['mock_info']['header_deps'].append(h_rpc)

print(json.dumps(tx_mock, indent=4))
