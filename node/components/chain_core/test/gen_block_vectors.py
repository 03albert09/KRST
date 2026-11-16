import hashlib
import struct

GENESIS_TIMESTAMP = 1793491200
GENESIS_TARGET = 0xFFFFFFFF


# Skrot SHA-256
def sha256(data):
    return hashlib.sha256(data).digest()


# Bajty transakcji w ukladzie krst_tx_t
def tx_bytes(tx_type, nonce, sender, recipient, amount, signature):
    return struct.pack("<BI33s33sQ64s", tx_type, nonce, sender, recipient, amount, signature)


# Przykladowa transakcja, te same wartosci buduje sample_tx() w test_block.c
def sample_tx(i):
    return tx_bytes(
        1,
        i,
        bytes([0x02]) + bytes([i]) * 32,
        bytes([0x03]) + bytes([i + 1]) * 32,
        1000 + i,
        bytes([i]) * 64,
    )


# Korzen Merkle listy transakcji, jak w block_merkle_root()
def merkle_root(txs):
    level = [sha256(b"\x00" + tx) for tx in txs]
    while len(level) > 1:
        parents = []
        for i in range(0, len(level), 2):
            if i + 1 < len(level):
                parents.append(sha256(b"\x01" + level[i] + level[i + 1]))
            else:
                parents.append(level[i])
        level = parents
    return level[0]


# Bajty naglowka bloku w ukladzie block_header_t
def header_bytes(height, prev_hash, root, timestamp, target, nonce):
    return struct.pack("<I32s32sIII", height, prev_hash, root, timestamp, target, nonce)


# Tablica C z podanymi bajtami
def c_array(name, data):
    body = ", ".join(f"0x{b:02x}" for b in data)
    return f"static const uint8_t {name}[{len(data)}] = {{ {body} }};"


txs = [sample_tx(i) for i in range(1, 10)]
header = header_bytes(7, bytes(range(32)), bytes(range(32, 64)), 1793500000, 0x00040000, 123456)
genesis = header_bytes(0, bytes(32), bytes(32), GENESIS_TIMESTAMP, GENESIS_TARGET, 0)

print("// Plik generowany przez gen_block_vectors.py. Nie edytowac recznie.")
print("#pragma once")
print("#include <stdint.h>")
print()
for name, data in [
    ("BV_TX_BYTES", txs[0]),
    ("BV_TX_SIGNING_HASH", sha256(txs[0][:79])),
    ("BV_HEADER_BYTES", header),
    ("BV_HEADER_HASH", sha256(header)),
    ("BV_MERKLE_1", merkle_root(txs[:1])),
    ("BV_MERKLE_2", merkle_root(txs[:2])),
    ("BV_MERKLE_3", merkle_root(txs[:3])),
    ("BV_MERKLE_9", merkle_root(txs[:9])),
    ("BV_GENESIS_HASH", sha256(genesis)),
]:
    print(c_array(name, data))
