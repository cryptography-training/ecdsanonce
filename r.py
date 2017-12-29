#!/usr/bin/env python3

import sys
import glob

sys.path.insert(0, 'pycoin')
from pycoin.block import Block
from pycoin.tx.script.tools import get_opcode, opcode_list
from pycoin.tx.script.check_signature import parse_signature_blob, delete_subscript, bin_script
from pycoin.tx.script.der import UnexpectedDER
from pycoin.serialize import b2h_rev, h2b, h2b_rev, stream_to_bytes
from pycoin.ecdsa.secp256k1 import secp256k1_generator
from pycoin.encoding import sec_to_public_pair, EncodingError, secret_exponent_to_wif

tx_db = dict()
for filename in glob.glob("*.bin"):
    block = Block.parse(open(filename, "rb"))
    for tx in block.txs:
        tx_db[tx.hash()] = tx

def opcode_data(script):
    opcodes = []
    pc = 0
    while pc < len(script):
        try: opcode, data, pc = get_opcode(script, pc)
        except: return None
        opcodes.append(data)
    return opcodes

for filename in glob.glob("*.bin"):
    block = Block.parse(open(filename, "rb"))
    for tx in block.txs:
        for tx_in_idx, tx_in in enumerate(tx.txs_in):
            if tx.is_coinbase(): continue
            tx.unspents_from_db(tx_db, ignore_missing=True)
            if not tx.is_signature_ok(tx_in_idx): continue
            tx_out_script = tx.unspents[tx_in_idx].script
            to_sign = []
            def signature_for_hash_type_f(hash_type, script):
                h = tx.signature_hash(script, tx_in_idx, hash_type)
                to_sign.append(h)
                return h
            if not tx_in.verify(tx_out_script, signature_for_hash_type_f,
                lock_time=tx.lock_time, tx_version=tx.version): continue
            if len(to_sign) < 1: continue
            signature_hash = to_sign[0]

            stack = opcode_data(tx_in.script)
            if stack is None or len(stack) != 2: continue
            pair_blob = stack.pop()
            sig_blob = stack.pop()
            try: sig_pair, signature_type = parse_signature_blob(sig_blob)
            except: continue
            public_pair = sec_to_public_pair(pair_blob)
            r, s = sig_pair
            x, y = public_pair

            print("Address:", tx_in.bitcoin_address())
            print("r:", r)
            print("s:", s)
            print("x:", x)
            print("y:", y)
            print("h:", signature_hash)
            # print("Verifies:", secp256k1_generator.verify(public_pair, signature_hash, sig_pair))
