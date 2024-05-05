import argparse
import ckb
import json

# Dump full transaction data for [ckb-debugger](https://github.com/nervosnetwork/ckb-standalone-debugger) to use.

parser = argparse.ArgumentParser()
parser.add_argument('--file', type=str, help='transaction file')
parser.add_argument('--hash', type=str, help='transaction hash')
parser.add_argument('--net', type=str, choices=['develop', 'mainnet', 'testnet'], default='develop')
args = parser.parse_args()

assert args.file or args.hash

if args.net == 'develop':
    ckb.config.upgrade('http://127.0.0.1:8114')
    ckb.config.current = ckb.config.develop
if args.net == 'mainnet':
    ckb.config.current = ckb.config.mainnet
if args.net == 'testnet':
    ckb.config.current = ckb.config.testnet

if args.file:
    tx_json = json.load(open(args.file))
if args.hash:
    tx_json = ckb.rpc.get_transaction(args.hash)['transaction']
tx = ckb.core.Transaction.json_decode(tx_json)

tx_mock = {
    'mock_info': {
        'inputs': [],
        'cell_deps': [],
        'header_deps': []
    },
    'tx': tx.json(),
}

for i in tx.raw.inputs:
    i_tx_rpc = ckb.rpc.get_transaction(f'0x{i.previous_output.tx_hash.hex()}')
    i_tx = ckb.core.Transaction.json_decode(i_tx_rpc['transaction'])
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
    c_tx_rpc = ckb.rpc.get_transaction(f'0x{c.out_point.tx_hash.hex()}')
    c_tx = ckb.core.Transaction.json_decode(c_tx_rpc['transaction'])
    c_output = c_tx.raw.outputs[c.out_point.index]
    c_data = c_tx.raw.outputs_data[c.out_point.index]
    c_header = c_tx_rpc['tx_status']['block_hash']
    tx_mock['mock_info']['cell_deps'].append({
        'cell_dep': c.json(),
        'output': c_output.json(),
        'data': f'0x{c_data.hex()}',
        'header': c_header,
    })
    if c.dep_type != 1:
        continue
    for e in ckb.molecule.decode_fixvec(c_data):
        o = ckb.core.OutPoint.molecule_decode(e)
        o_tx_rpc = ckb.rpc.get_transaction(f'0x{o.tx_hash.hex()}')
        o_tx = ckb.core.Transaction.json_decode(o_tx_rpc['transaction'])
        o_output = o_tx.raw.outputs[o.index]
        o_data = o_tx.raw.outputs_data[o.index]
        o_header = o_tx_rpc['tx_status']['block_hash']
        tx_mock['mock_info']['cell_deps'].append({
            'cell_dep': ckb.core.CellDep(o, 0).json(),
            'output': o_output.json(),
            'data': f'0x{o_data.hex()}',
            'header': o_header,
        })
for h in tx.raw.header_deps:
    h_rpc = ckb.rpc.get_header(f'0x{h.hex()}')
    tx_mock['mock_info']['header_deps'].push(h_rpc)

print(json.dumps(tx_mock, indent=4))
