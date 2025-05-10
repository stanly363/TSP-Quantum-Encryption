import base64, hmac, hashlib, json, os, random, numpy as np
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# ---------------- Key Setup ----------------

def generate_graph(n=50, max_distance=100):
    g = np.random.randint(1, max_distance, size=(n, n))
    np.fill_diagonal(g, 0)
    return ((g + g.T) // 2).tolist()

def generate_optimal_tour(n=50):
    tour = list(range(n))
    random.shuffle(tour)
    return tour

def generate_noisy_tour(tour, level=0.7):
    t = tour.copy()
    for _ in range(int(len(t) * level)):
        i, j = random.sample(range(len(t)), 2)
        t[i], t[j] = t[j], t[i]
    return t

def add_padding(tour, extra=10, n=50):
    return tour + [random.randint(0, n - 1) for _ in range(extra)]

def derive_shared_key_symmetric_with_nonce(tour1, tour2, nonce):
    combined = bytes(sorted(tour1) + sorted(tour2))
    return hashlib.sha256(nonce + combined).digest()

# ---------------- Signature ----------------

def generate_signing_keypair():
    priv = ed25519.Ed25519PrivateKey.generate()
    pub = priv.public_key()
    return priv, pub

def save_signing_keys(priv, pub, dir="keys"):
    os.makedirs(dir, exist_ok=True)
    with open(f"{dir}/private_signing_key.pem", "wb") as f:
        f.write(priv.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    with open(f"{dir}/public_verification_key.pem", "wb") as f:
        f.write(pub.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))

def load_signing_keys():
    with open("keys/private_signing_key.pem", "rb") as f:
        priv = serialization.load_pem_private_key(f.read(), password=None)
    with open("keys/public_verification_key.pem", "rb") as f:
        pub = serialization.load_pem_public_key(f.read())
    return priv, pub

# ---------------- Crypto Utilities ----------------

def aes_encrypt(plaintext, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    return iv + encryptor.update(plaintext.encode()) + encryptor.finalize()

def aes_decrypt(ciphertext, key):
    iv, ct = ciphertext[:16], ciphertext[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    return (decryptor.update(ct) + decryptor.finalize()).decode()

def compute_hmac(key, msg):
    return hmac.new(key, msg, hashlib.sha256).hexdigest()

def verify_hmac(key, msg, tag):
    return hmac.compare_digest(compute_hmac(key, msg), tag)

def sign_payload(priv, data):
    return priv.sign(data)

def verify_signature(pub, data, sig):
    try:
        pub.verify(sig, data)
        return True
    except Exception:
        return False

def b64e(b): return base64.b64encode(b).decode()
def b64d(s): return base64.b64decode(s)

# ---------------- Legacy Tour-Based Encoder ----------------

def tour_encode(message, tour, graph):
    bits = ''.join(f'{ord(c):08b}' for c in message)
    output = []
    idx = 0
    for bit in bits:
        curr = tour[idx % len(tour)]
        if bit == '0':
            nxt = tour[(idx + 1) % len(tour)]
        else:
            candidates = list(set(range(len(graph))) - {tour[(idx + 1) % len(tour)]})
            nxt = random.choice(candidates)
        output.append((curr, nxt))
        idx += 1
    return output

def tour_decode(tour_output, tour):
    bits = ''
    idx = 0
    for curr, nxt in tour_output:
        expected = tour[(idx + 1) % len(tour)]
        bits += '0' if nxt == expected else '1'
        idx += 1
    chars = [chr(int(bits[i:i+8], 2)) for i in range(0, len(bits), 8)]
    return ''.join(chars)

# ---------------- Key Exchange ----------------

def simulate_key_exchange():
    # Alice's private tour and noisy version
    alice_tour = generate_optimal_tour()
    alice_noisy = add_padding(generate_noisy_tour(alice_tour), 10)
    nonce = os.urandom(16)  # Alice chooses the nonce

    # Alice sends (alice_noisy, nonce) to Bob

    # Bob's private tour and key derivation using Alice's noisy tour
    bob_tour = generate_optimal_tour()
    bob_key = derive_shared_key_symmetric_with_nonce(bob_tour, alice_noisy, nonce)

    # Alice derives the same key using her private tour and nonce
    alice_key = derive_shared_key_symmetric_with_nonce(alice_tour, alice_noisy, nonce)

    # Assert that both keys are the same
    assert alice_key == bob_key, "Key mismatch!"

    return alice_key, nonce, alice_tour, bob_tour


# ---------------- Main ----------------

def main():
    if not os.path.exists("keys/private_signing_key.pem"):
        priv, pub = generate_signing_keypair()
        save_signing_keys(priv, pub)
    else:
        priv, pub = load_signing_keys()

    # TSP Key Exchange
    shared_key, nonce, alice_tour, _ = simulate_key_exchange()
    print("[✔] Shared Key:", shared_key.hex())
    print("[✔] Nonce:", nonce.hex())

    # Graph for legacy tour encoding
    graph = generate_graph()
    print("[✔] Generated Graph and Tour")

    # Legacy Tour-Based Encoding
    legacy_tour_output = tour_encode("Legacy Test", alice_tour, graph)
    print("[✔] Legacy Encoded Tour:", legacy_tour_output)

    # AES-Based Encryption
    aes_ciphertext = aes_encrypt("This is the AES encrypted message.", shared_key)
    hmac_tag = compute_hmac(shared_key, aes_ciphertext)

    package = {
        "nonce": b64e(nonce),
        "ciphertext": b64e(aes_ciphertext),
        "hmac": hmac_tag,
        "legacy_tour_output": legacy_tour_output
    }

    serialized = json.dumps(package).encode()
    signature = sign_payload(priv, serialized)

    final_message = {
        "payload": b64e(serialized),
        "signature": b64e(signature)
    }

    print("\n[✔] Final Signed & Encrypted Package:\n", json.dumps(final_message, indent=2))

    # Receiving Simulation
    print("\n[✔] Simulating Receiver...\n")
    received = json.loads(json.dumps(final_message))
    payload = json.loads(b64d(received["payload"]))
    received_sig = b64d(received["signature"])

    if verify_signature(pub, b64d(received["payload"]), received_sig):
        print("[✔] Signature verified.")
        nonce = b64d(payload["nonce"])
        ciphertext = b64d(payload["ciphertext"])
        if verify_hmac(shared_key, ciphertext, payload["hmac"]):
            plaintext = aes_decrypt(ciphertext, shared_key)
            print("[✔] AES Decrypted:", plaintext)
            decoded_legacy = tour_decode(payload["legacy_tour_output"], alice_tour)
            print("[✔] Legacy Decoded:", decoded_legacy)
        else:
            print("[❌] HMAC verification failed.")
    else:
        print("[❌] Signature verification failed.")

if __name__ == "__main__":
    main()
