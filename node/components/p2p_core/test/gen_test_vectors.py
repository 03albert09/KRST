import hashlib
import hmac
import struct

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed, decode_dss_signature
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

MAGIC = 0xF1B9


# Tablica C z podanymi bajtami
def c_array(name, data):
    body = ", ".join(f"0x{b:02x}" for b in data)
    return f"static const uint8_t {name}[{len(data)}] = {{ {body} }};"


# Skrocony HMAC-SHA256 ramki P2P, jak w node_crypto_calc_msg_hmac()
def frame_hmac(key, cmd, seq, payload):
    header = struct.pack("<HHII", MAGIC, cmd, len(payload), seq)
    return hmac.new(key, header + payload, hashlib.sha256).digest()[:16]


key = bytes(range(32))
payload = b"hello"
chal_a = bytes([0xA0 + i % 16 for i in range(32)])
chal_b = bytes([0xB0 + i % 16 for i in range(32)])
pk_a = bytes([0x02]) + bytes(range(1, 33))
pk_b = bytes([0x03]) + bytes(range(33, 65))
shared = bytes([0x5A] * 32)

handshake = hashlib.sha256(b"P2P-MITM-V1" + chal_a + chal_b + pk_a + pk_b).digest()
session = hashlib.sha256(b"P2P-SESSION-KEY-V1" + shared + chal_a + chal_b).digest()

private_key = ec.derive_private_key(0x1234567890ABCDEF, ec.SECP256K1())
public_key = private_key.public_key().public_bytes(Encoding.X962, PublicFormat.CompressedPoint)
message_hash = hashlib.sha256(b"krst test vector").digest()
der_signature = private_key.sign(
    message_hash, ec.ECDSA(Prehashed(hashes.SHA256()), deterministic_signing=True)
)
r, s = decode_dss_signature(der_signature)
signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")


# Klucz z poprawnym prefiksem, ale z X, dla ktorego na secp256k1 nie ma punktu
def off_curve_pubkey():
    p = 2**256 - 2**32 - 977
    x = 1
    while pow((x**3 + 7) % p, (p - 1) // 2, p) == 1:
        x += 1
    return bytes([0x02]) + x.to_bytes(32, "big")


print("// Plik generowany przez gen_test_vectors.py. Nie edytowac recznie.")
print("#pragma once")
print("#include <stdint.h>")
print()
for name, data in [
    ("TV_KEY", key),
    ("TV_PAYLOAD", payload),
    ("TV_HMAC_WITH_PAYLOAD", frame_hmac(key, 8, 7, payload)),
    ("TV_HMAC_NO_PAYLOAD", frame_hmac(key, 9, 1, b"")),
    ("TV_CHAL_A", chal_a),
    ("TV_CHAL_B", chal_b),
    ("TV_PK_A", pk_a),
    ("TV_PK_B", pk_b),
    ("TV_SHARED", shared),
    ("TV_HANDSHAKE_HASH", handshake),
    ("TV_SESSION_KEY", session),
    ("TV_ECDSA_PUBKEY", public_key),
    ("TV_ECDSA_HASH", message_hash),
    ("TV_ECDSA_SIGNATURE", signature),
    ("TV_OFF_CURVE_PUBKEY", off_curve_pubkey()),
]:
    print(c_array(name, data))
