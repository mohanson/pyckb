import ckb.config
import ckb.core
import ckb.rpc
import itertools
import json

sender_prikey = ckb.core.PriKey(0x0000000000000000000000000000000000000000000000000000000000000002)
accept_addr = 'ckt1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsqt4z78ng4yutl5u6xsv27ht6q08mhujf8s2r0n40'
sender_pubkey = sender_prikey.pubkey()
sender_args = ckb.core.hash(sender_pubkey.pack())[:20]
sender_script = ckb.core.Script(
    ckb.config.current.scripts.secp256k1_blake160.code_hash,
    ckb.config.current.scripts.secp256k1_blake160.hash_type,
    sender_args,
)
sender_capacity = 0
accept_script = ckb.core.address_decode(accept_addr)
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

search = ckb.rpc.get_cells_iter({
    'script': sender_script.json(),
    'script_type': 'lock',
    'filter': {
        'script_len_range': ['0x0', '0x1']
    }
})
for cell in search:
    cell_out_point = ckb.core.OutPoint(
        bytearray.fromhex(cell['out_point']['tx_hash'][2:]),
        int(cell['out_point']['index'], 16)
    )
    cell_capacity = int(cell['output']['capacity'], 16)
    cell_input = ckb.core.CellInput(0, cell_out_point)

    sender_capacity += cell_capacity
    tx.raw.inputs.append(cell_input)
    if len(tx.witnesses) == 0:
        tx.witnesses.append(ckb.core.WitnessArgs(
            bytearray([0 for _ in range(65)]),
            None,
            None,
        ).pack())
    else:
        tx.witnesses.append(bytearray())

accept_capacity = sender_capacity - len(tx.pack()) - 4
tx.raw.outputs[0].capacity = accept_capacity

sign_data = bytearray()
sign_data.extend(tx.raw.hash())
for witness in tx.witnesses:
    sign_data.extend(len(witness).to_bytes(8, 'little'))
    sign_data.extend(witness)
sign_data_hash = ckb.core.hash(sign_data)
sign = sender_prikey.sign(sign_data_hash)

tx.witnesses[0] = ckb.core.WitnessArgs(sign, None, None).pack()

tx_hash = ckb.rpc.send_transaction(tx.json(), 'well_known_scripts_only')
print(tx_hash)
