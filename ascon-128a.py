import struct
import time

# Constants
ROUND_CONSTANTS = [
    0x0000000f0f0f0f0f, 0x0000000e0e0e0e0e, 0x0000000d0d0d0d0d,
    0x0000000c0c0c0c0c, 0x0000000b0b0b0b0b, 0x0000000a0a0a0a0a,
    0x0000000909090909, 0x0000000808080808, 0x0000000707070707,
    0x0000000606060606, 0x0000000505050505, 0x0000000404040404
]

# Substitution Layer (S-Box)
def substitution_layer(state):
    for i in range(len(state)):
        x = state[i]
        state[i] ^= ((x >> 1) & (x >> 2)) & 0xFFFFFFFFFFFFFFFF
    return state

# Permutation Function
def permutation(state, rounds):
    for i in range(rounds):
        # Step 1: Add round constant
        state[0] ^= ROUND_CONSTANTS[i] & 0xFFFFFFFFFFFFFFFF
        # Step 2: Substitution Layer
        state = substitution_layer(state)
        # Step 3: Linear Diffusion Layer (simplified)
        state[0] = ((state[0] << 19) | (state[0] >> (64 - 19))) & 0xFFFFFFFFFFFFFFFF  # Rotate left and constrain
    return state

# Initialization for Ascon-128a
def ascon_128a_init(key, nonce):
    state = [0] * 5  # Initialize 320-bit state
    state[0] = (key ^ nonce) & 0xFFFFFFFFFFFFFFFF
    state = permutation(state, 12)  # Apply p12
    return state

# Absorption for Ascon-128a
def absorb_128a(state, plaintext):
    # Absorb 16-byte blocks for higher throughput
    for i in range(0, len(plaintext), 16):
        block = plaintext[i:i + 16]
        state[0] ^= struct.unpack(">Q", block[:8].ljust(8, b'\x00'))[0] & 0xFFFFFFFFFFFFFFFF
        state[1] ^= struct.unpack(">Q", block[8:].ljust(8, b'\x00'))[0] & 0xFFFFFFFFFFFFFFFF
        state = permutation(state, 8)  # Apply p8
    return state

# Squeeze for Ascon-128a
def squeeze_128a(state, length):
    ciphertext = b""
    for _ in range(length // 8):
        ciphertext += struct.pack(">Q", state[0] & 0xFFFFFFFFFFFFFFFF)
        state = permutation(state, 8)  # Apply p8
    return ciphertext

# Ascon-128a Encryption with Timing Analysis
def ascon_128a_encrypt(key, nonce, plaintext):
    start_time = time.perf_counter()  # Start timer
    state = ascon_128a_init(key, nonce)  # Initialization
    state = absorb_128a(state, plaintext)  # Absorption phase
    ciphertext = squeeze_128a(state, len(plaintext))  # Squeeze phase
    end_time = time.perf_counter()  # End timer

    # Metrics
    execution_time = end_time - start_time
    output_size = len(ciphertext)
    
    # Results
    print("Ascon-128a Metrics:")
    print(f"- Execution Time: {execution_time:.6f} seconds")
    print(f"- Output Size: {output_size} bytes")
    return ciphertext, execution_time

# Test Ascon-128a
if __name__ == "__main__":
    key = 0xdeadbeefcafebabedeadbeefcafebabe  # 128-bit key
    nonce = 0x1234567890abcdef  # 64-bit nonce
    plaintext = b"Hello IoT! This is a test for Ascon-128a encryption."
    
    ciphertext, exec_time = ascon_128a_encrypt(key, nonce, plaintext)
    print("Ciphertext (Hex):", ciphertext.hex())
