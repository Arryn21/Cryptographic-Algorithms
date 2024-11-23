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

# Initialization for Ascon-MAC
def ascon_mac_init(key):
    state = [0] * 5  # Initialize 320-bit state
    state[0] ^= key & 0xFFFFFFFFFFFFFFFF  # XOR the key into the state
    state[1] ^= 0x80400c0600000000  # Initialization constant for MAC
    state = permutation(state, 12)  # Apply p12
    return state

# Absorption for MAC
def absorb_mac(state, input_data):
    for i in range(0, len(input_data), 8):
        block = input_data[i:i + 8]
        state[0] ^= struct.unpack(">Q", block.ljust(8, b'\x00'))[0] & 0xFFFFFFFFFFFFFFFF
        state = permutation(state, 8)  # Apply p8
    return state

# Squeeze for MAC
def squeeze_mac(state, mac_length):
    mac = b""
    for _ in range(mac_length // 8):
        mac += struct.pack(">Q", state[0] & 0xFFFFFFFFFFFFFFFF)
        state = permutation(state, 8)  # Apply p8
    return mac

# Ascon-MAC Function with Timing Analysis
def ascon_mac(key, input_data, mac_length=16):
    start_time = time.perf_counter()  # Start timer
    state = ascon_mac_init(key)  # Initialize state with key
    state = absorb_mac(state, input_data)  # Absorb input data
    mac = squeeze_mac(state, mac_length)  # Squeeze phase to generate MAC
    end_time = time.perf_counter()  # End timer

    # Metrics
    execution_time = end_time - start_time
    mac_size = len(mac)
    
    # Results
    print("Ascon-MAC Metrics:")
    print(f"- Execution Time: {execution_time:.6f} seconds")
    print(f"- MAC Size: {mac_size} bytes")
    return mac, execution_time

# Test Ascon-MAC
if __name__ == "__main__":
    key = 0xdeadbeefcafebabedeadbeefcafebabe  # 128-bit key
    input_data = b"Authenticate this data using Ascon-MAC!"
    mac, exec_time = ascon_mac(key, input_data, mac_length=16)  # 128-bit MAC
    print("MAC (Hex):", mac.hex())
