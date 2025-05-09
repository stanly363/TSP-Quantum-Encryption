import base64
import hmac
import hashlib
import json
import os
import random
import numpy as np

def generate_graph(n=50, max_distance=100):
    graph = np.random.randint(1, max_distance, size=(n, n))
    np.fill_diagonal(graph, 0)
    graph = (graph + graph.T) // 2  # Make symmetric
    return graph.tolist()  # Convert to list for JSON compatibility

def generate_optimal_tour(n=50):
    tour = list(range(n))
    random.shuffle(tour)
    return tour

import hashlib

def generate_noisy_tour(optimal_tour, noise_level=0.3):
    """Obfuscate the tour by introducing random swaps."""
    tour = optimal_tour.copy()
    n_swaps = int(len(tour) * noise_level)
    for _ in range(n_swaps):
        i, j = random.sample(range(len(tour)), 2)
        tour[i], tour[j] = tour[j], tour[i]
    return tour

def derive_shared_key(my_tour, received_noisy_tour):
    """Derives a shared key by XORing both tours and hashing."""
    combined = [a ^ b for a, b in zip(my_tour, received_noisy_tour)]
    combined_bytes = bytes(combined)
    return hashlib.sha256(combined_bytes).digest()

def derive_shared_key_symmetric(tour1, tour2):
    """
    Deterministically derive the same shared key from two tours by:
    - Sorting both tours
    - Concatenating
    - Hashing the result
    """
    sorted1 = sorted(tour1)
    sorted2 = sorted(tour2)
    combined = bytes(sorted1 + sorted2)
    return hashlib.sha256(combined).digest()


def save_hmac_key(key: bytes, path="keys/hmac_key.key"):
    """Save HMAC key to a file."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(key)

def load_hmac_key(path="keys/hmac_key.key") -> bytes:
    """Load HMAC key from a file."""
    with open(path, "rb") as f:
        return f.read()


def save_key_pair(graph, optimal_tour, directory="keys"):
    os.makedirs(directory, exist_ok=True)
    with open(os.path.join(directory, "public_key.json"), "w") as pub_file:
        json.dump({"graph": graph}, pub_file)
    with open(os.path.join(directory, "private_key.json"), "w") as priv_file:
        json.dump({"optimal_tour": optimal_tour}, priv_file)

def load_public_key(path="keys/public_key.json"):
    with open(path, "r") as f:
        return json.load(f)["graph"]

def load_private_key(path="keys/private_key.json"):
    with open(path, "r") as f:
        return json.load(f)["optimal_tour"]


def b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode()

def b64decode(data: str) -> bytes:
    return base64.b64decode(data)

def compute_hmac(key: bytes, message: bytes) -> str:
    return hmac.new(key, message, hashlib.sha256).hexdigest()

def verify_hmac(key: bytes, message: bytes, tag: str) -> bool:
    expected_tag = compute_hmac(key, message)
    return hmac.compare_digest(expected_tag, tag)

def generate_nonce(length=16):
    return os.urandom(length)

def encrypt(message, graph, optimal_tour, hmac_key):
    bits = ''.join(f'{ord(c):08b}' for c in message)
    tour_output = []
    idx = 0
    n = len(graph)

    nonce = generate_nonce()

    for bit in bits:
        current_city = optimal_tour[idx % len(optimal_tour)]
        if bit == '0':
            next_city = optimal_tour[(idx + 1) % len(optimal_tour)]
        else:
            neighbors = list(set(range(n)) - {optimal_tour[(idx + 1) % len(optimal_tour)]})
            next_city = random.choice(neighbors)
        tour_output.append((current_city, next_city))
        idx += 1

    # Serialize and encode ciphertext
    payload = {
        "nonce": b64encode(nonce),
        "tour": tour_output
    }
    payload_bytes = json.dumps(payload).encode()
    tag = compute_hmac(hmac_key, payload_bytes)

    final_package = {
        "payload": b64encode(payload_bytes),
        "hmac": tag
    }

    return json.dumps(final_package)

def decrypt(package_json, optimal_tour, hmac_key):
    package = json.loads(package_json)
    payload_bytes = b64decode(package["payload"])
    tag = package["hmac"]

    if not verify_hmac(hmac_key, payload_bytes, tag):
        raise ValueError("Integrity check failed: HMAC does not match!")

    payload = json.loads(payload_bytes.decode())
    tour_output = payload["tour"]

    bits = ''
    idx = 0
    for current_city, next_city in tour_output:
        expected_next = optimal_tour[(idx + 1) % len(optimal_tour)]
        bits += '0' if next_city == expected_next else '1'
        idx += 1

    chars = [chr(int(bits[i:i+8], 2)) for i in range(0, len(bits), 8)]
    return ''.join(chars)

# --- Key Management ---

# Shared graph
graph = generate_graph()

# Alice and Bob's private tours
alice_tour = generate_optimal_tour()
bob_tour = generate_optimal_tour()

# Each sends a noisy tour to the other
alice_noisy = generate_noisy_tour(alice_tour)
bob_noisy = generate_noisy_tour(bob_tour)

# Alice derives the key using her private + Bob's noisy tour
alice_shared_key = derive_shared_key_symmetric(alice_tour, bob_noisy)

# Bob derives the key using his private + Alice's noisy tour
bob_shared_key = derive_shared_key_symmetric(bob_tour, alice_noisy)

print("Do shared keys match?", alice_shared_key == bob_shared_key)


# Generate and save keys (only once)
graph = generate_graph()
optimal_tour = generate_optimal_tour()
save_key_pair(graph, optimal_tour)

# Generate and save HMAC key (only once)
hmac_key = os.urandom(32)
save_hmac_key(hmac_key)

# --- In a new session or after restart ---

# Load keys
public_graph = load_public_key()
private_tour = load_private_key()
hmac_key = load_hmac_key()

# Encrypt a message
message = "Secure Message"
ciphertext = encrypt(message, public_graph, private_tour, hmac_key)
print("Ciphertext:", ciphertext)

# Decrypt the message
try:
    decrypted_message = decrypt(ciphertext, private_tour, hmac_key)
    print("Decrypted message:", decrypted_message)
except ValueError as e:
    print("Integrity check failed:", str(e))
