#!/usr/bin/env python3
import os
import sys
import csv
import time
import secrets
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, x25519, ed25519, padding
from cryptography.hazmat.primitives.asymmetric import mlkem, mldsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305, AESGCMSIV

def main():
    if len(sys.argv) < 2:
        print("Usage: python my_project.py <output_directory>")
        sys.exit(1)

    output_dir = sys.argv[1]
    os.makedirs(output_dir, exist_ok=True)
    raw_csv_path = os.path.join(output_dir, "raw.csv")

    # Open CSV and write header
    with open(raw_csv_path, mode="w", newline="") as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(["part", "algorithm", "operation", "message_bytes", "run", "nanoseconds"])

        def record(part, alg, op, msg_bytes, run_idx, ns):
            writer.writerow([part, alg, op, msg_bytes, run_idx, ns])

        # ==========================================
        # PART 1: KEY ESTABLISHMENT (KEM)
        # ==========================================
        kem_configs = [
            ("RSA-OAEP-3072", lambda: rsa.generate_private_key(public_exponent=65537, key_size=3072), 21),
            ("RSA-OAEP-7680", lambda: rsa.generate_private_key(public_exponent=65537, key_size=7680), 21),
            ("ECDH-P-256", lambda: ec.generate_private_key(ec.SECP256R1()), 101),
            ("ECDH-P-384", lambda: ec.generate_private_key(ec.SECP384R1()), 101),
            ("ECDH-P-521", lambda: ec.generate_private_key(ec.SECP521R1()), 101),
            ("X25519", lambda: x25519.X25519PrivateKey.generate(), 101),
            ("ML-KEM-768", lambda: mlkem.MLKEM768PrivateKey.generate(), 101),
            ("ML-KEM-1024", lambda: mlkem.MLKEM1024PrivateKey.generate(), 101),
        ]

        for alg_name, keygen_func, num_runs in kem_configs:
            # 1. Keygen Timing
            for r in range(num_runs):
                t0 = time.perf_counter_ns()
                priv = keygen_func()
                t1 = time.perf_counter_ns()
                record("kem", alg_name, "keygen", 0, r, t1 - t0)

            # Generate static key pair for encapsulate/decapsulate tests
            priv_static = keygen_func()
            pub_static = priv_static.public_key()

            if "RSA-OAEP" in alg_name:
                oaep_pad = padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
                rand_data = secrets.token_bytes(32)
                ciphertext = pub_static.encrypt(rand_data, oaep_pad)

                # Encapsulate
                for r in range(101):
                    rd = secrets.token_bytes(32)
                    t0 = time.perf_counter_ns()
                    _ = pub_static.encrypt(rd, oaep_pad)
                    t1 = time.perf_counter_ns()
                    record("kem", alg_name, "encapsulate", 0, r, t1 - t0)

                # Decapsulate
                for r in range(101):
                    t0 = time.perf_counter_ns()
                    _ = priv_static.decrypt(ciphertext, oaep_pad)
                    t1 = time.perf_counter_ns()
                    record("kem", alg_name, "decapsulate", 0, r, t1 - t0)

            elif "ECDH" in alg_name or alg_name == "X25519":
                if alg_name == "X25519":
                    ephem_priv = x25519.X25519PrivateKey.generate()
                    ciphertext = ephem_priv.public_key().public_bytes_raw()
                else:
                    curve = priv_static.curve
                    ephem_priv = ec.generate_private_key(curve)
                    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
                    ciphertext = ephem_priv.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)

                # Encapsulate
                for r in range(101):
                    if alg_name == "X25519":
                        e_priv = x25519.X25519PrivateKey.generate()
                        t0 = time.perf_counter_ns()
                        _ = e_priv.exchange(pub_static)
                        ct = e_priv.public_key().public_bytes_raw()
                        t1 = time.perf_counter_ns()
                    else:
                        e_priv = ec.generate_private_key(pub_static.curve)
                        t0 = time.perf_counter_ns()
                        _ = e_priv.exchange(ec.ECDH(), pub_static)
                        ct = e_priv.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
                        t1 = time.perf_counter_ns()
                    record("kem", alg_name, "encapsulate", 0, r, t1 - t0)

                # Decapsulate
                for r in range(101):
                    t0 = time.perf_counter_ns()
                    if alg_name == "X25519":
                        ephem_pub = x25519.X25519PublicKey.from_public_bytes(ciphertext)
                        _ = priv_static.exchange(ephem_pub)
                    else:
                        ephem_pub = ec.EllipticCurvePublicKey.from_encoded_point(pub_static.curve, ciphertext)
                        _ = priv_static.exchange(ec.ECDH(), ephem_pub)
                    t1 = time.perf_counter_ns()
                    record("kem", alg_name, "decapsulate", 0, r, t1 - t0)

            elif "ML-KEM" in alg_name:
                _, ciphertext = pub_static.encapsulate()

                # Encapsulate
                for r in range(101):
                    t0 = time.perf_counter_ns()
                    _ = pub_static.encapsulate()
                    t1 = time.perf_counter_ns()
                    record("kem", alg_name, "encapsulate", 0, r, t1 - t0)

                # Decapsulate
                for r in range(101):
                    t0 = time.perf_counter_ns()
                    _ = priv_static.decapsulate(ciphertext)
                    t1 = time.perf_counter_ns()
                    record("kem", alg_name, "decapsulate", 0, r, t1 - t0)

        # ==========================================
        # PART 2: DIGITAL SIGNATURES
        # ==========================================
        sig_configs = [
            ("RSA-PSS-3072", lambda: rsa.generate_private_key(public_exponent=65537, key_size=3072), 21),
            ("RSA-PSS-7680", lambda: rsa.generate_private_key(public_exponent=65537, key_size=7680), 21),
            ("ECDSA-P-256", lambda: ec.generate_private_key(ec.SECP256R1()), 101),
            ("ECDSA-P-384", lambda: ec.generate_private_key(ec.SECP384R1()), 101),
            ("ECDSA-P-521", lambda: ec.generate_private_key(ec.SECP521R1()), 101),
            ("Ed25519", lambda: ed25519.Ed25519PrivateKey.generate(), 101),
            ("ML-DSA-44", lambda: mldsa.MLDSA44PrivateKey.generate(), 101),
            ("ML-DSA-65", lambda: mldsa.MLDSA65PrivateKey.generate(), 101),
            ("ML-DSA-87", lambda: mldsa.MLDSA87PrivateKey.generate(), 101),
        ]

        message_1kiB = secrets.token_bytes(1024)

        for alg_name, keygen_func, num_runs in sig_configs:
            # 1. Keygen Timing
            for r in range(num_runs):
                t0 = time.perf_counter_ns()
                priv = keygen_func()
                t1 = time.perf_counter_ns()
                record("signature", alg_name, "keygen", 0, r, t1 - t0)

            priv_static = keygen_func()
            pub_static = priv_static.public_key()

            if "RSA-PSS" in alg_name:
                pss_pad = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)
                sig = priv_static.sign(message_1kiB, pss_pad, hashes.SHA256())

                for r in range(101):
                    t0 = time.perf_counter_ns()
                    _ = priv_static.sign(message_1kiB, pss_pad, hashes.SHA256())
                    t1 = time.perf_counter_ns()
                    record("signature", alg_name, "sign", 0, r, t1 - t0)

                for r in range(101):
                    t0 = time.perf_counter_ns()
                    pub_static.verify(sig, message_1kiB, pss_pad, hashes.SHA256())
                    t1 = time.perf_counter_ns()
                    record("signature", alg_name, "verify", 0, r, t1 - t0)

            elif "ECDSA" in alg_name:
                h = hashes.SHA256() if "256" in alg_name else (hashes.SHA384() if "384" in alg_name else hashes.SHA512())
                sig = priv_static.sign(message_1kiB, ec.ECDSA(h))

                for r in range(101):
                    t0 = time.perf_counter_ns()
                    _ = priv_static.sign(message_1kiB, ec.ECDSA(h))
                    t1 = time.perf_counter_ns()
                    record("signature", alg_name, "sign", 0, r, t1 - t0)

                for r in range(101):
                    t0 = time.perf_counter_ns()
                    pub_static.verify(sig, message_1kiB, ec.ECDSA(h))
                    t1 = time.perf_counter_ns()
                    record("signature", alg_name, "verify", 0, r, t1 - t0)

            elif alg_name == "Ed25519" or "ML-DSA" in alg_name:
                sig = priv_static.sign(message_1kiB)

                for r in range(101):
                    t0 = time.perf_counter_ns()
                    _ = priv_static.sign(message_1kiB)
                    t1 = time.perf_counter_ns()
                    record("signature", alg_name, "sign", 0, r, t1 - t0)

                for r in range(101):
                    t0 = time.perf_counter_ns()
                    pub_static.verify(sig, message_1kiB)
                    t1 = time.perf_counter_ns()
                    record("signature", alg_name, "verify", 0, r, t1 - t0)

        # ==========================================
        # PART 3: AUTHENTICATED ENCRYPTION (AEAD)
        # ==========================================
        aead_configs = [
            ("AES-128-GCM", 16, lambda k: AESGCM(k)),
            ("AES-256-GCM", 32, lambda k: AESGCM(k)),
            ("ChaCha20-Poly1305", 32, lambda k: ChaCha20Poly1305(k)),
            ("AES-256-GCM-SIV", 32, lambda k: AESGCMSIV(k)),
        ]

        message_lengths = [64, 1024, 16384, 1048576]

        for alg_name, key_len, cipher_factory in aead_configs:
            for m_len in message_lengths:
                key = secrets.token_bytes(key_len)
                msg = secrets.token_bytes(m_len)
                cipher = cipher_factory(key)
                nonce = secrets.token_bytes(12)
                ciphertext = cipher.encrypt(nonce, msg, None)

                # Encrypt runs
                for r in range(101):
                    n_enc = secrets.token_bytes(12)
                    t0 = time.perf_counter_ns()
                    _ = cipher.encrypt(n_enc, msg, None)
                    t1 = time.perf_counter_ns()
                    record("aead", alg_name, "encrypt", m_len, r, t1 - t0)

                # Decrypt runs
                for r in range(101):
                    t0 = time.perf_counter_ns()
                    _ = cipher.decrypt(nonce, ciphertext, None)
                    t1 = time.perf_counter_ns()
                    record("aead", alg_name, "decrypt", m_len, r, t1 - t0)

    print(f"Benchmark completed successfully. Results written to {raw_csv_path}")

if __name__ == "__main__":
    main()