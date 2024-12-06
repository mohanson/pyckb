import argparse
import math
import pyckb

# Attempt to withdraw all funds from Dao. When running the test case of pyckb by 'pytest -v', a part of ckb will be
# locked in Dao. Use this script to recover this part of the funds.

parser = argparse.ArgumentParser()
parser.add_argument('--net', type=str, choices=['develop', 'mainnet', 'testnet'], default='develop')
parser.add_argument('--prikey', type=str, help='private key')
args = parser.parse_args()

if args.net == 'develop':
    pyckb.config.upgrade('http://127.0.0.1:8114')
    pyckb.config.current = pyckb.config.develop
if args.net == 'mainnet':
    pyckb.config.current = pyckb.config.mainnet
if args.net == 'testnet':
    pyckb.config.current = pyckb.config.testnet

user = pyckb.wallet.Wallet(int(args.prikey, 0))
for e in user.dao_livecell():
    if e['output_data'] == '0x0000000000000000':
        out_point = pyckb.core.OutPoint.json_decode(e['out_point'])
        hash = user.dao_prepare(out_point)
        pyckb.rpc.wait(f'0x{hash.hex()}')
        print(f'0x{hash.hex()}')
    else:
        deposit_block_number_byte = bytearray.fromhex(e['output_data'][2:])
        deposit_block_number = int.from_bytes(deposit_block_number_byte, 'little')
        deposit_block_header = pyckb.rpc.get_header_by_number(hex(deposit_block_number))
        deposit_block_epoch = pyckb.core.epoch_decode(int(deposit_block_header['epoch'], 16))
        deposit_block_epoch_float = deposit_block_epoch[0] + deposit_block_epoch[1] / deposit_block_epoch[2]
        prepare_block_header = pyckb.rpc.get_header_by_number(e['block_number'])
        prepare_block_epoch = pyckb.core.epoch_decode(int(prepare_block_header['epoch'], 16))
        prepare_block_epoch_float = prepare_block_epoch[0] + prepare_block_epoch[1] / prepare_block_epoch[2]
        extract_since_delay = math.ceil((prepare_block_epoch_float - deposit_block_epoch_float) / 180) * 180
        extract_since_epoch_float = deposit_block_epoch_float + extract_since_delay
        current_block_epoch = pyckb.core.epoch_decode(int(pyckb.rpc.get_tip_header()['epoch'], 16))
        current_block_epoch_float = current_block_epoch[0] + current_block_epoch[1] / current_block_epoch[2]
        if current_block_epoch_float < extract_since_epoch_float:
            break
        out_point = pyckb.core.OutPoint.json_decode(e['out_point'])
        hash = user.dao_extract(out_point)
        pyckb.rpc.wait(f'0x{hash.hex()}')
        print(f'0x{hash.hex()}')
