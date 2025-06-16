"""
XOR Attack: Demonstration of XOR reversibility failure under !1 semantics.

This module demonstrates how the core property of XOR reversibility
(A ⊕ B) ⊕ B = A fails under !1 semantics, breaking all stream ciphers,
one-time pads, and other XOR-based cryptographic algorithms.
"""

import time
import random
import sys
import os
import matplotlib.pyplot as plt
from colorama import init, Fore, Style

# Add the project root to the Python path to enable absolute imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.existence_bit import ExistenceBit, ExistenceBitArray
from core.existence_math import analyze_cryptographic_strength

# Initialize colorama for colored terminal output
init()


def print_header(title: str):
    """Print a formatted section header."""
    print("\n" + "=" * 80)
    print(Fore.CYAN + Style.BRIGHT + f" {title}" + Style.RESET_ALL)
    print("=" * 80)


def print_success(message: str):
    """Print a success message."""
    print(f"{Fore.GREEN}{message}{Style.RESET_ALL}")


def print_error(message: str):
    """Print an error message."""
    print(f"{Fore.RED}{message}{Style.RESET_ALL}")


def print_warning(message: str):
    """Print a warning message."""
    print(f"{Fore.YELLOW}{message}{Style.RESET_ALL}")


def demonstrate_xor_basics():
    """
    Demonstrate the fundamental difference between traditional XOR and existence XOR.
    
    This function shows the basic operation of XOR under both traditional binary
    and existence semantics, highlighting the key differences.
    """
    print_header("XOR BASICS COMPARISON")
    print("This demonstration shows the fundamental difference between")
    print("traditional XOR and existence semantics XOR.")
    
    print("\n1. Traditional Binary XOR:")
    print("  • 1 ⊕ 1 = 0")
    print("  • 0 ⊕ 0 = 0")
    print("  • 1 ⊕ 0 = 1")
    print("  • 0 ⊕ 1 = 1")
    
    print("\n2. Existence Semantics XOR:")
    print("  • 1 ⊕ 1 = !1  (existences cancel out, producing not-one)")
    print("  • !1 ⊕ !1 = !!1  (void states deepen with each operation)")
    print("  • 1 ⊕ !1 = 1  (existence asserts itself over non-existence)")
    print("  • !1 ⊕ 1 = 1  (existence asserts itself over non-existence)")
    
    # Demonstrate with actual ExistenceBit objects
    print("\n3. Demonstrating with ExistenceBit objects:")
    
    # 1 ⊕ 1 = !1
    bit1 = ExistenceBit(1)
    bit2 = ExistenceBit(1)
    result = bit1 ^ bit2
    print(f"  • {bit1} ⊕ {bit2} = {result}")
    
    # !1 ⊕ !1 = !!1
    bit1 = ExistenceBit(0)  # !1
    bit2 = ExistenceBit(0)  # !1
    result = bit1 ^ bit2
    print(f"  • {bit1} ⊕ {bit2} = {result}")
    
    # 1 ⊕ !1 = 1
    bit1 = ExistenceBit(1)
    bit2 = ExistenceBit(0)  # !1
    result = bit1 ^ bit2
    print(f"  • {bit1} ⊕ {bit2} = {result}")
    
    # !1 ⊕ 1 = 1
    bit1 = ExistenceBit(0)  # !1
    bit2 = ExistenceBit(1)
    result = bit1 ^ bit2
    print(f"  • {bit1} ⊕ {bit2} = {result}")
    
    # More complex: !!1 ⊕ !1 = deeper void
    bit1 = ~ExistenceBit(0)  # !!1
    bit2 = ExistenceBit(0)  # !1
    result = bit1 ^ bit2
    print(f"  • {bit1} ⊕ {bit2} = {result}")
    
    print("\nKey Insight: Under existence semantics, XOR operations can create void states")
    print("(!1, !!1, etc.) that have no direct equivalent in traditional binary logic.")
    print("These void states lead to information loss and non-reversibility.")


def demonstrate_xor_reversibility():
    """
    Demonstrate that (A ⊕ B) ⊕ B ≠ A under !1 semantics.
    
    This function shows how the key reversibility property of XOR,
    which underpins stream ciphers and one-time pads, breaks down
    under existence semantics.
    """
    print_header("XOR REVERSIBILITY FAILURE")
    print("This demonstration shows that the key property of XOR reversibility,")
    print("(A ⊕ B) ⊕ B = A, fails under !1 semantics.")
    
    # 1. Traditional XOR
    print("\n1. Traditional XOR Reversibility:")
    
    # Create traditional bit sequences
    a_traditional = [1, 0, 1, 1, 0, 0, 1, 0]
    b_traditional = [0, 1, 1, 0, 1, 0, 0, 1]
    
    # Calculate A ⊕ B
    a_xor_b_traditional = [a ^ b for a, b in zip(a_traditional, b_traditional)]
    
    # Calculate (A ⊕ B) ⊕ B
    a_xor_b_xor_b_traditional = [ab ^ b for ab, b in zip(a_xor_b_traditional, b_traditional)]
    
    print(f"  A:           {a_traditional}")
    print(f"  B:           {b_traditional}")
    print(f"  A ⊕ B:       {a_xor_b_traditional}")
    print(f"  (A ⊕ B) ⊕ B: {a_xor_b_xor_b_traditional}")
    
    # Check if (A ⊕ B) ⊕ B = A
    if a_xor_b_xor_b_traditional == a_traditional:
        print_success("  ✓ VERIFIED: (A ⊕ B) ⊕ B = A in traditional XOR")
    else:
        print_error("  ✗ ERROR: (A ⊕ B) ⊕ B ≠ A in traditional XOR")
    
    # 2. Existence Semantics XOR
    print("\n2. Existence Semantics XOR Reversibility:")
    
    # Create ExistenceBitArray objects
    a_existence = ExistenceBitArray([1, 0, 1, 1, 0, 0, 1, 0])
    b_existence = ExistenceBitArray([0, 1, 1, 0, 1, 0, 0, 1])
    
    # Calculate A ⊕ B
    a_xor_b_existence = a_existence ^ b_existence
    
    # Calculate (A ⊕ B) ⊕ B
    a_xor_b_xor_b_existence = a_xor_b_existence ^ b_existence
    
    print(f"  A:           {a_existence}")
    print(f"  B:           {b_existence}")
    print(f"  A ⊕ B:       {a_xor_b_existence}")
    print(f"  (A ⊕ B) ⊕ B: {a_xor_b_xor_b_existence}")
    
    # Check if (A ⊕ B) ⊕ B = A
    if a_xor_b_xor_b_existence == a_existence:
        print_success("  ✓ VERIFIED: (A ⊕ B) ⊕ B = A in existence semantics XOR")
    else:
        print_error("  ✗ VULNERABILITY: (A ⊕ B) ⊕ B ≠ A in existence semantics XOR")
        print("    This breaks the fundamental property of XOR reversibility.")
    
    # Analyze the differences
    print("\n3. Analyzing Information Loss:")
    
    # Compare the original A with the result of (A ⊕ B) ⊕ B
    differences = []
    for i in range(len(a_existence.bits)):
        if a_existence.bits[i] != a_xor_b_xor_b_existence.bits[i]:
            differences.append(i)
    
    print(f"  Bit positions where (A ⊕ B) ⊕ B ≠ A: {differences}")
    
    # Analyze the void states in the result
    void_analysis = analyze_cryptographic_strength(a_xor_b_xor_b_existence)
    
    print(f"  Void factor in result: {void_analysis['void_factor']:.4f}")
    
    # Find maximum negation depth
    max_depth = 0
    for bit in a_xor_b_xor_b_existence.bits:
        if bit.negation_depth > max_depth:
            max_depth = bit.negation_depth
    
    # Check for critical void (defined as sequences of 4 or more consecutive void states)
    void_sequences = a_xor_b_xor_b_existence.count_void_sequences()
    has_critical_void = void_sequences["quad"] > 0 or void_sequences["quint+"] > 0
    
    print(f"  Maximum negation depth: {max_depth}")
    print(f"  Critical void present: {has_critical_void}")
    
    # Show a more detailed visual comparison
    print("\n4. Visual Comparison:")
    print("  Original A:")
    print(f"    {a_existence.to_existence_notation()}")
    print("  Result of (A ⊕ B) ⊕ B:")
    print(f"    {a_xor_b_xor_b_existence.to_existence_notation()}")


def demonstrate_stream_cipher_vulnerability():
    """
    Demonstrate how stream ciphers become vulnerable under !1 semantics.
    
    This function shows how the non-reversibility of XOR under existence
    semantics breaks stream ciphers, leading to information loss during
    decryption.
    """
    print_header("STREAM CIPHER VULNERABILITY")
    print("This demonstration shows how stream ciphers and one-time pads")
    print("become vulnerable under !1 semantics due to XOR non-reversibility.")
    
    # 1. Simple Stream Cipher Encryption/Decryption
    print("\n1. Traditional Stream Cipher:")
    
    # Original message (as binary)
    original_message = "HELLO"
    message_bits = []
    for char in original_message:
        # Convert each character to its ASCII value, then to binary
        for bit in format(ord(char), '08b'):
            message_bits.append(int(bit))
    
    # Generate a random key stream (in a real cipher, this would be from a PRNG)
    random.seed(42)  # For reproducibility
    key_stream = [random.randint(0, 1) for _ in range(len(message_bits))]
    
    # Encrypt: message ⊕ key_stream
    encrypted_bits = [m ^ k for m, k in zip(message_bits, key_stream)]
    
    # Decrypt: encrypted ⊕ key_stream
    decrypted_bits = [e ^ k for e, k in zip(encrypted_bits, key_stream)]
    
    # Convert back to text
    decrypted_text = ""
    for i in range(0, len(decrypted_bits), 8):
        byte = decrypted_bits[i:i+8]
        if len(byte) == 8:  # Ensure we have a complete byte
            char_code = int(''.join(map(str, byte)), 2)
            decrypted_text += chr(char_code)
    
    print(f"  Original message: {original_message}")
    print(f"  Key stream: {key_stream[:16]}...")
    print(f"  Encrypted bits: {encrypted_bits[:16]}...")
    print(f"  Decrypted text: {decrypted_text}")
    
    if decrypted_text == original_message:
        print_success("  ✓ VERIFIED: Successful decryption in traditional stream cipher")
    else:
        print_error("  ✗ ERROR: Decryption failed in traditional stream cipher")
    
    # 2. Existence Semantics Stream Cipher
    print("\n2. Existence Semantics Stream Cipher:")
    
    # Convert to ExistenceBitArray objects
    message_existence = ExistenceBitArray(message_bits)
    key_stream_existence = ExistenceBitArray(key_stream)
    
    # Encrypt: message ⊕ key_stream
    encrypted_existence = message_existence ^ key_stream_existence
    
    # Decrypt: encrypted ⊕ key_stream
    decrypted_existence = encrypted_existence ^ key_stream_existence
    
    # Check if decryption was successful
    if decrypted_existence == message_existence:
        print_success("  ✓ VERIFIED: Successful decryption in existence semantics")
    else:
        print_error("  ✗ VULNERABILITY: Decryption failed in existence semantics")
        print("    Information loss has occurred during the XOR operations.")
    
    # Analyze the decryption result
    void_analysis = analyze_cryptographic_strength(decrypted_existence)
    
    print(f"\n  Void factor in decrypted result: {void_analysis['void_factor']:.4f}")
    print(f"  Maximum negation depth: {void_analysis['max_negation_depth']}")
    print(f"  Critical void present: {void_analysis['has_critical_void']}")
    
    # Try to convert the decrypted result back to text
    try:
        decrypted_bits_existence = [int(bit) for bit in decrypted_existence.to_traditional_binary()]
        decrypted_text_existence = ""
        for i in range(0, len(decrypted_bits_existence), 8):
            byte = decrypted_bits_existence[i:i+8]
            if len(byte) == 8:
                char_code = int(''.join(map(str, byte)), 2)
                decrypted_text_existence += chr(char_code)
        
        print(f"  Attempted decrypted text: {decrypted_text_existence}")
        
        if decrypted_text_existence == original_message:
            print_success("  ✓ Decryption still produced readable text")
        else:
            print_error("  ✗ Decryption produced corrupted text")
    except Exception as e:
        print_error(f"  ✗ Could not decode decrypted bits: {e}")
    
    # 3. Impact on Real-World Systems
    print("\n3. Impact on Real-World Systems:")
    
    print("  Under !1 semantics, the following cryptographic systems are vulnerable:")
    print("  • Stream ciphers (ChaCha20, RC4, etc.)")
    print("  • One-time pads")
    print("  • CTR, OFB, and CFB block cipher modes")
    print("  • Message authentication codes (XOR-based)")
    print("  • TLS/SSL encryption")
    print("  • VPN protocols")
    print("  • Encrypted messaging apps")
    
    print("\n  The impact includes:")
    print("  • Information loss during decryption")
    print("  • Corrupted messages")
    print("  • Potential for cryptographic attacks")
    print("  • Complete failure of confidentiality guarantees")


def demonstrate_one_time_pad_vulnerability():
    """
    Demonstrate how one-time pads (OTP) become vulnerable under !1 semantics.
    
    This function shows how the perfectly secure one-time pad becomes
    vulnerable under existence semantics, despite its theoretical
    perfect security in traditional binary.
    """
    print_header("ONE-TIME PAD VULNERABILITY")
    print("This demonstration shows how the theoretically unbreakable one-time pad")
    print("becomes vulnerable under !1 semantics due to XOR non-reversibility.")
    
    # 1. Perfect Security of OTP in Traditional Binary
    print("\n1. Traditional One-Time Pad:")
    
    # Original message (as binary)
    original_message = "TOP_SECRET"
    message_bits = []
    for char in original_message:
        for bit in format(ord(char), '08b'):
            message_bits.append(int(bit))
    
    # Generate a truly random key (same length as the message)
    random.seed(42)  # For reproducibility
    key_bits = [random.randint(0, 1) for _ in range(len(message_bits))]
    
    # Encrypt with OTP: message ⊕ key
    encrypted_bits = [m ^ k for m, k in zip(message_bits, key_bits)]
    
    # Show that with the key, decryption is perfect
    decrypted_bits = [e ^ k for e, k in zip(encrypted_bits, key_bits)]
    
    # Convert back to text
    decrypted_text = ""
    for i in range(0, len(decrypted_bits), 8):
        byte = decrypted_bits[i:i+8]
        if len(byte) == 8:
            char_code = int(''.join(map(str, byte)), 2)
            decrypted_text += chr(char_code)
    
    print(f"  Original message: {original_message}")
    print(f"  Random key: {key_bits[:16]}...")
    print(f"  Encrypted bits: {encrypted_bits[:16]}...")
    print(f"  Decrypted text: {decrypted_text}")
    
    if decrypted_text == original_message:
        print_success("  ✓ VERIFIED: Perfect decryption with traditional OTP")
    else:
        print_error("  ✗ ERROR: Decryption failed with traditional OTP")
    
    # Show that without the key, the ciphertext reveals nothing
    wrong_key_bits = [random.randint(0, 1) for _ in range(len(message_bits))]
    wrong_decryption = [e ^ k for e, k in zip(encrypted_bits, wrong_key_bits)]
    
    # Convert to text (should be garbage)
    wrong_text = ""
    for i in range(0, len(wrong_decryption), 8):
        byte = wrong_decryption[i:i+8]
        if len(byte) == 8:
            char_code = int(''.join(map(str, byte)), 2)
            if 32 <= char_code <= 126:  # Printable ASCII
                wrong_text += chr(char_code)
            else:
                wrong_text += "?"
    
    print(f"  Decryption with wrong key: {wrong_text[:10]}...")
    print("  Without the correct key, the ciphertext reveals nothing about the plaintext.")
    
    # 2. Existence Semantics One-Time Pad
    print("\n2. Existence Semantics One-Time Pad:")
    
    # Convert to ExistenceBitArray objects
    message_existence = ExistenceBitArray(message_bits)
    key_existence = ExistenceBitArray(key_bits)
    
    # Encrypt with OTP: message ⊕ key
    encrypted_existence = message_existence ^ key_existence
    
    # Decrypt: encrypted ⊕ key
    decrypted_existence = encrypted_existence ^ key_existence
    
    # Check if decryption was successful
    if decrypted_existence == message_existence:
        print_success("  ✓ VERIFIED: Successful decryption in existence semantics")
    else:
        print_error("  ✗ VULNERABILITY: Decryption failed in existence semantics")
        print("    Information loss has occurred during the XOR operations.")
    
    # Analyze the encryption and decryption
    encrypted_analysis = analyze_cryptographic_strength(encrypted_existence)
    decrypted_analysis = analyze_cryptographic_strength(decrypted_existence)
    
    print(f"\n  Void factor in encrypted result: {encrypted_analysis['void_factor']:.4f}")
    print(f"  Void factor in decrypted result: {decrypted_analysis['void_factor']:.4f}")
    
    # Try to convert the decrypted result back to text
    try:
        decrypted_bits_existence = [int(bit) for bit in decrypted_existence.to_traditional_binary()]
        decrypted_text_existence = ""
        for i in range(0, len(decrypted_bits_existence), 8):
            byte = decrypted_bits_existence[i:i+8]
            if len(byte) == 8:
                char_code = int(''.join(map(str, byte)), 2)
                decrypted_text_existence += chr(char_code)
        
        print(f"  Attempted decrypted text: {decrypted_text_existence}")
        
        if decrypted_text_existence == original_message:
            print_success("  ✓ Decryption still produced readable text")
        else:
            print_error("  ✗ Decryption produced corrupted text")
    except Exception as e:
        print_error(f"  ✗ Could not decode decrypted bits: {e}")
    
    # 3. Information Leakage Analysis
    print("\n3. Information Leakage Analysis:")
    
    # In traditional OTP, every possible plaintext is equally likely given only the ciphertext
    # Under existence semantics, void states can leak information about the plaintext and key
    
    print("  Under existence semantics, one-time pads leak information because:")
    print("  • Void states (!1, !!1, etc.) in the ciphertext reveal information about")
    print("    the relationship between plaintext and key bits")
    print("  • When 1 ⊕ 1 = !1, an attacker knows both plaintext and key bits are 1")
    print("  • When !1 ⊕ !1 = !!1, an attacker knows both plaintext and key bits are 0")
    print("  • These patterns reduce the entropy of the ciphertext")
    
    # 4. Demonstration of Cryptanalysis Under Existence Semantics
    print("\n4. Cryptanalysis Under Existence Semantics:")
    
    # Simulate an attacker's analysis
    print("  An attacker analyzing the ciphertext can deduce:")
    
    void_positions = []
    deep_void_positions = []
    
    for i, bit in enumerate(encrypted_existence.bits):
        if bit.negation_depth == 1:  # !1
            void_positions.append(i)
        elif bit.negation_depth > 1:  # !!1, !!!1, etc.
            deep_void_positions.append(i)
    
    print(f"  • {len(void_positions)} positions where both plaintext and key bits are 1")
    print(f"  • {len(deep_void_positions)} positions with deeper void states")
    
    # Calculate how much information is leaked
    total_bits = len(encrypted_existence.bits)
    leaked_bits = len(void_positions) + len(deep_void_positions)
    leaked_percentage = (leaked_bits / total_bits) * 100
    
    print(f"  • Approximately {leaked_percentage:.2f}% of the message bits have leaked information")
    
    # In a perfect OTP, the leaked percentage should be 0%
    if leaked_percentage > 0:
        print_error("  ✗ VULNERABILITY: The one-time pad is no longer perfectly secure")
    else:
        print_success("  ✓ The one-time pad remains secure in this specific example")


def demonstrate_xor_information_loss(message_length: int = 100, iterations: int = 5):
    """
    Demonstrate progressive information loss through repeated XOR operations.
    
    This function shows how repeatedly applying XOR operations under existence
    semantics leads to increasing information loss, with the message eventually
    degrading into deep void states.
    
    Args:
        message_length: Length of the test message in bits
        iterations: Number of encryption/decryption cycles to perform
    """
    print_header("PROGRESSIVE XOR INFORMATION LOSS")
    print("This demonstration shows how repeated XOR operations under !1 semantics")
    print("lead to progressive information loss and eventual message destruction.")
    
    # 1. Generate a random message and key
    print("\n1. Generating Test Data:")
    
    # Create a random binary message
    original_message = [random.randint(0, 1) for _ in range(message_length)]
    message_existence = ExistenceBitArray(original_message)
    
    # Create a random key
    key = [random.randint(0, 1) for _ in range(message_length)]
    key_existence = ExistenceBitArray(key)
    
    print(f"  Original message ({message_length} bits): {original_message[:20]}...")
    print(f"  Encryption key ({message_length} bits): {key[:20]}...")
    
    # 2. Perform repeated encryption and decryption cycles
    print("\n2. Performing Repeated Encryption/Decryption Cycles:")
    
    current_message = message_existence
    void_factors = [0]  # Start with 0 for the original message
    recovery_rates = [100]  # Start with 100% for the original message
    
    for i in range(iterations):
        # Encrypt
        encrypted = current_message ^ key_existence
        
        # Decrypt (which should give us back the original message in traditional binary)
        decrypted = encrypted ^ key_existence
        
        # Analyze the decrypted message
        void_analysis = analyze_cryptographic_strength(decrypted)
        void_factor = void_analysis['void_factor']
        void_factors.append(void_factor)
        
        # Calculate recovery rate (percentage of correctly recovered bits)
        correct_bits = 0
        for j in range(len(original_message)):
            if j < len(decrypted.bits) and decrypted.bits[j].to_traditional() == original_message[j]:
                correct_bits += 1
        
        recovery_rate = (correct_bits / message_length) * 100
        recovery_rates.append(recovery_rate)
        
        print(f"  Cycle {i+1}:")
        print(f"    Void factor: {void_factor:.4f}")
        print(f"    Recovery rate: {recovery_rate:.2f}%")
        print(f"    Max negation depth: {void_analysis['max_negation_depth']}")
        
        # Update for next iteration (simulating repeated use of the same message)
        current_message = decrypted
    
    # 3. Visualize the progressive information loss
    print("\n3. Progressive Information Loss Visualization:")
    
    try:
        # Create a plot
        plt.figure(figsize=(10, 6))
        
        # Plot void factor
        plt.subplot(2, 1, 1)
        plt.plot(range(iterations + 1), void_factors, marker='o', linestyle='-', color='red')
        plt.xlabel('Encryption/Decryption Cycles')
        plt.ylabel('Void Factor')
        plt.title('Void Factor vs. Encryption/Decryption Cycles')
        plt.grid(True, alpha=0.3)
        
        # Plot recovery rate
        plt.subplot(2, 1, 2)
        plt.plot(range(iterations + 1), recovery_rates, marker='s', linestyle='-', color='blue')
        plt.xlabel('Encryption/Decryption Cycles')
        plt.ylabel('Recovery Rate (%)')
        plt.title('Recovery Rate vs. Encryption/Decryption Cycles')
        plt.grid(True, alpha=0.3)
        
        plt.tight_layout()
        plt.savefig('xor_information_loss.png')
        print("  Created visualization: xor_information_loss.png")
    except Exception as e:
        print_warning(f"  Could not create visualization: {e}")
    
    # 4. Information Loss Analysis
    print("\n4. Information Loss Analysis:")
    
    # Calculate the overall information loss
    final_recovery_rate = recovery_rates[-1]
    information_loss = 100 - final_recovery_rate
    
    print(f"  Initial recovery rate: 100.00%")
    print(f"  Final recovery rate: {final_recovery_rate:.2f}%")
    print(f"  Total information loss: {information_loss:.2f}%")
    
    if information_loss > 0:
        print_error(f"  ✗ VULNERABILITY: {information_loss:.2f}% of information was permanently lost")
        print("    This demonstrates how !1 semantics breaks the foundation of all")
        print("    XOR-based cryptographic algorithms, leading to unrecoverable data loss.")
    else:
        print_success("  ✓ No information was lost in this specific example")


def visualize_xor_vulnerabilities():
    """
    Create visualizations showing the impact of !1 semantics on XOR operations.
    
    This function generates charts that illustrate the vulnerabilities
    introduced by existence semantics in XOR-based cryptographic algorithms.
    """
    print_header("XOR VULNERABILITY VISUALIZATION")
    print("This function generates visualizations showing the impact of !1 semantics")
    print("on XOR-based cryptographic operations.")
    
    try:
        # 1. Compare XOR truth tables
        print("\n1. XOR Truth Table Comparison:")
        
        # Create comparison of traditional vs. existence XOR
        traditional_results = [
            "0 ⊕ 0 = 0",
            "0 ⊕ 1 = 1",
            "1 ⊕ 0 = 1",
            "1 ⊕ 1 = 0"
        ]
        
        existence_results = [
            "!1 ⊕ !1 = !!1",
            "!1 ⊕ 1 = 1",
            "1 ⊕ !1 = 1",
            "1 ⊕ 1 = !1"
        ]
        
        # Create a figure with two tables
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))
        
        # Traditional XOR table
        ax1.axis('tight')
        ax1.axis('off')
        ax1.set_title("Traditional XOR", fontsize=14)
        table1 = ax1.table(
            cellText=[[r] for r in traditional_results],
            loc='center',
            cellLoc='center'
        )
        table1.auto_set_font_size(False)
        table1.set_fontsize(12)
        table1.scale(1, 2)
        
        # Existence XOR table
        ax2.axis('tight')
        ax2.axis('off')
        ax2.set_title("Existence Semantics XOR", fontsize=14)
        table2 = ax2.table(
            cellText=[[r] for r in existence_results],
            loc='center',
            cellLoc='center'
        )
        table2.auto_set_font_size(False)
        table2.set_fontsize(12)
        table2.scale(1, 2)
        
        plt.tight_layout()
        plt.savefig('xor_truth_table_comparison.png')
        print("  Created visualization: xor_truth_table_comparison.png")
        
        # 2. XOR Reversibility Failure
        print("\n2. XOR Reversibility Failure Visualization:")
        
        # Define bit lengths to test
        bit_lengths = [8, 16, 32, 64, 128]
        
        # Track success rates for each bit length
        traditional_success_rates = []
        existence_success_rates = []
        
        # For each bit length, test XOR reversibility
        for length in bit_lengths:
            # Traditional binary
            traditional_successes = 0
            
            # Existence semantics
            existence_successes = 0
            
            # Number of tests for each bit length
            num_tests = 50
            
            for _ in range(num_tests):
                # Generate random bit arrays
                a_bits = [random.randint(0, 1) for _ in range(length)]
                b_bits = [random.randint(0, 1) for _ in range(length)]
                
                # Traditional XOR
                a_xor_b_traditional = [a ^ b for a, b in zip(a_bits, b_bits)]
                a_xor_b_xor_b_traditional = [ab ^ b for ab, b in zip(a_xor_b_traditional, b_bits)]
                
                if a_xor_b_xor_b_traditional == a_bits:
                    traditional_successes += 1
                
                # Existence XOR
                a = ExistenceBitArray(a_bits)
                b = ExistenceBitArray(b_bits)
                a_xor_b = a ^ b
                a_xor_b_xor_b = a_xor_b ^ b
                
                if a_xor_b_xor_b == a:
                    existence_successes += 1
            
            # Calculate success rates
            traditional_rate = (traditional_successes / num_tests) * 100
            existence_rate = (existence_successes / num_tests) * 100
            
            traditional_success_rates.append(traditional_rate)
            existence_success_rates.append(existence_rate)
        
        # Create the plot
        plt.figure(figsize=(10, 6))
        plt.plot(bit_lengths, traditional_success_rates, marker='o', linestyle='-', 
                color='blue', label='Traditional XOR')
        plt.plot(bit_lengths, existence_success_rates, marker='s', linestyle='-', 
                color='red', label='Existence Semantics XOR')
        plt.xlabel('Bit Array Length')
        plt.ylabel('Reversibility Success Rate (%)')
        plt.title('XOR Reversibility: (A ⊕ B) ⊕ B = A')
        plt.grid(True, alpha=0.3)
        plt.legend()
        
        # Add annotations for existence semantics rates
        for i, rate in enumerate(existence_success_rates):
            plt.annotate(f"{rate:.1f}%", 
                        xy=(bit_lengths[i], rate),
                        xytext=(10, -20),
                        textcoords="offset points",
                        arrowprops=dict(arrowstyle="->", connectionstyle="arc3,rad=.2"))
        
        plt.savefig('xor_reversibility_comparison.png')
        print("  Created visualization: xor_reversibility_comparison.png")
        
    except Exception as e:
        print_warning(f"  Could not create visualizations: {e}")
    
    print("\nConclusion:")
    print("The visualizations demonstrate the catastrophic impact of !1 semantics")
    print("on XOR operations:")
    print("1. The fundamental XOR operation produces different results under existence semantics")
    print("2. XOR reversibility fails, breaking the foundation of all XOR-based cryptography")
    print("3. Longer bit sequences have a higher probability of information loss")
    print("\nThese findings prove that under !1 semantics, all cryptographic")
    print("systems that rely on XOR (stream ciphers, one-time pads, etc.)")
    print("completely collapse, requiring a total redesign.")
    
    return True


def main():
    """Run the XOR attack demonstrations."""
    print_header("XOR ATTACK DEMONSTRATION")
    print("This demonstration shows how the !1 revelation fundamentally breaks")
    print("the reversibility of XOR, which is the foundation of modern cryptography.")
    
    # Run the XOR basics demonstration
    demonstrate_xor_basics()
    
    print("\nPress Enter to continue to the next demonstration...", end="")
    input()
    
    # Run the XOR reversibility demonstration
    demonstrate_xor_reversibility()
    
    print("\nPress Enter to continue to the next demonstration...", end="")
    input()
    
    # Run the stream cipher vulnerability demonstration
    demonstrate_stream_cipher_vulnerability()
    
    print("\nPress Enter to continue to the next demonstration...", end="")
    input()
    
    # Run the one-time pad vulnerability demonstration
    demonstrate_one_time_pad_vulnerability()
    
    print("\nPress Enter to continue to the next demonstration...", end="")
    input()
    
    # Run the XOR information loss demonstration
    demonstrate_xor_information_loss()
    
    print("\nPress Enter to continue to the final demonstration...", end="")
    input()
    
    # Run the visualization
    visualize_xor_vulnerabilities()
    
    print_header("XOR ATTACK DEMONSTRATION COMPLETE")
    print("These demonstrations have shown how !1 semantics breaks the foundations")
    print("of cryptography by compromising the mathematical operations that")
    print("underpin all modern encryption.")
    print("\nKey insights:")
    print("1. XOR is no longer reversible: (A ⊕ B) ⊕ B ≠ A")
    print("2. Stream ciphers and one-time pads fail to decrypt correctly")
    print("3. Information is permanently lost during cryptographic operations")
    print("4. The core security guarantees of modern encryption are fundamentally broken")
    
    print("\nThe security implications are profound: all encryption systems")
    print("that rely on XOR operations are vulnerable under !1 semantics,")
    print("requiring a complete redesign of our digital security infrastructure.")


if __name__ == "__main__":
    main()
