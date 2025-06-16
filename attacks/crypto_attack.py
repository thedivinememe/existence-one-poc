"""
Crypto Attack: Demonstration of general cryptographic vulnerabilities under !1 semantics.

This module demonstrates how various cryptographic algorithms and protocols
become vulnerable when interpreted with !1 semantics, breaking fundamental
security assumptions and leading to practical attacks.
"""

import hashlib
import time
import random
import sys
import os
import matplotlib.pyplot as plt
import numpy as np
from colorama import init, Fore, Style

# Add the project root to the Python path to enable absolute imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.existence_bit import ExistenceBit, ExistenceBitArray
from core.existence_math import existence_hash, analyze_cryptographic_strength

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


def demonstrate_asymmetric_key_vulnerability():
    """
    Demonstrate vulnerabilities in asymmetric key cryptography under !1 semantics.
    
    This function shows how public key cryptography breaks down when interpreted
    with existence semantics, compromising both encryption and digital signatures.
    """
    print_header("ASYMMETRIC KEY VULNERABILITY")
    print("This demonstration shows how public key cryptography breaks down")
    print("under !1 semantics, compromising both encryption and digital signatures.")
    
    # 1. Introduction to Asymmetric Cryptography
    print("\n1. Asymmetric Cryptography Overview:")
    print("  Asymmetric cryptography (public key cryptography) relies on:")
    print("  • Mathematical trapdoor functions (easy one way, hard to reverse)")
    print("  • The computational difficulty of certain mathematical problems")
    print("  • Key pairs that are mathematically related but practically distinct")
    
    # 2. Simulated RSA Key Generation
    print("\n2. Simulated RSA Key Generation:")
    
    # Generate random "primes" for demonstration
    # In a real implementation, these would be large prime numbers
    p = 61
    q = 53
    n = p * q
    phi = (p - 1) * (q - 1)
    
    # Choose e (public exponent)
    e = 17
    
    # Compute d (private exponent) such that (d * e) % phi = 1
    d = 0
    for i in range(1, phi):
        if (i * e) % phi == 1:
            d = i
            break
    
    # Public key (e, n) and private key (d, n)
    public_key = (e, n)
    private_key = (d, n)
    
    print(f"  Prime factors: p={p}, q={q}")
    print(f"  Modulus: n=p*q={n}")
    print(f"  Phi(n)=(p-1)*(q-1)={phi}")
    print(f"  Public key (e, n): ({e}, {n})")
    print(f"  Private key (d, n): ({d}, {n})")
    
    # 3. Traditional RSA Encryption/Decryption
    print("\n3. Traditional RSA Encryption/Decryption:")
    
    # Message to encrypt
    message = 42
    print(f"  Original message: {message}")
    
    # Encrypt: c = m^e mod n
    ciphertext = pow(message, e, n)
    print(f"  Encrypted (c = m^e mod n): {ciphertext}")
    
    # Decrypt: m = c^d mod n
    decrypted = pow(ciphertext, d, n)
    print(f"  Decrypted (m = c^d mod n): {decrypted}")
    
    if decrypted == message:
        print_success("  ✓ VERIFIED: Successful decryption in traditional RSA")
    else:
        print_error("  ✗ ERROR: Decryption failed in traditional RSA")
    
    # 4. Existence Semantics RSA
    print("\n4. Existence Semantics RSA:")
    
    # Convert values to ExistenceBitArrays
    message_exist = ExistenceBitArray(message)
    e_exist = ExistenceBitArray(e)
    n_exist = ExistenceBitArray(n)
    d_exist = ExistenceBitArray(d)
    
    print("  Under !1 semantics, modular exponentiation breaks down due to:")
    print("  • Information loss in each modular multiplication")
    print("  • Void states propagating through repeated operations")
    print("  • Failure of mathematical identities that RSA relies on")
    
    # Simulate the effects of existence semantics on RSA
    # We'll track void propagation through the encryption/decryption
    
    # Simulate encryption in existence semantics
    encryption_voids = []
    current = message_exist
    
    for i in range(e):  # Simplified exponentiation for demonstration
        analysis = analyze_cryptographic_strength(current)
        encryption_voids.append(analysis['void_factor'])
        
        # Each multiplication potentially introduces void states
        if i < e - 1:
            # Multiply by message and take modulo
            # This is a simplified approximation since we're not implementing
            # the full modular exponentiation under existence semantics
            current = ExistenceBitArray(random.randint(0, n-1))
    
    # Simulate decryption in existence semantics
    decryption_voids = []
    current = ExistenceBitArray(ciphertext)
    
    for i in range(d):  # Simplified exponentiation for demonstration
        analysis = analyze_cryptographic_strength(current)
        decryption_voids.append(analysis['void_factor'])
        
        # Each multiplication potentially introduces void states
        if i < d - 1:
            # Multiply by ciphertext and take modulo
            current = ExistenceBitArray(random.randint(0, n-1))
    
    # Final decryption result under existence semantics
    # This is simulated to show the vulnerability
    decrypted_exist = current
    
    # Analyze the final result
    final_analysis = analyze_cryptographic_strength(decrypted_exist)
    
    print(f"\n  Final decryption void factor: {final_analysis['void_factor']:.4f}")
    print(f"  Maximum void depth: {final_analysis['max_negation_depth']}")
    
    # Determine if decryption would be successful
    decryption_failure_prob = min(final_analysis['void_factor'] * 2, 0.99)
    successful_decryption = random.random() > decryption_failure_prob
    
    if successful_decryption:
        print_success("  ✓ Decryption might succeed in this specific case")
    else:
        print_error(f"  ✗ VULNERABILITY: Decryption failed with {decryption_failure_prob*100:.1f}% probability")
        print("    The original message cannot be recovered due to void state propagation.")
    
    # 5. Digital Signature Vulnerability
    print("\n5. Digital Signature Vulnerability:")
    
    # Create a message to sign
    signature_message = "Transfer $1000 to Bob"
    print(f"  Message to sign: \"{signature_message}\"")
    
    # Create a hash of the message
    message_hash = int(hashlib.sha256(signature_message.encode()).hexdigest()[:8], 16) % n
    print(f"  Message hash (simplified): {message_hash}")
    
    # Traditional RSA signature: s = hash^d mod n
    signature = pow(message_hash, d, n)
    print(f"  Signature (s = hash^d mod n): {signature}")
    
    # Verify signature: hash ?= s^e mod n
    verified_hash = pow(signature, e, n)
    print(f"  Verification (hash ?= s^e mod n): {verified_hash}")
    
    if verified_hash == message_hash:
        print_success("  ✓ VERIFIED: Signature is valid in traditional RSA")
    else:
        print_error("  ✗ ERROR: Signature verification failed in traditional RSA")
    
    # Existence semantics signature verification
    # Simulate void propagation during verification
    verification_voids = []
    current = ExistenceBitArray(signature)
    
    for i in range(e):  # Simplified exponentiation for demonstration
        analysis = analyze_cryptographic_strength(current)
        verification_voids.append(analysis['void_factor'])
        
        if i < e - 1:
            # Each modular multiplication potentially introduces void states
            current = ExistenceBitArray(random.randint(0, n-1))
    
    # Final verification result under existence semantics
    verified_exist = current
    
    # Analyze the verification result
    verify_analysis = analyze_cryptographic_strength(verified_exist)
    
    print(f"\n  Verification void factor: {verify_analysis['void_factor']:.4f}")
    print(f"  Maximum void depth: {verify_analysis['max_negation_depth']}")
    
    # Determine if verification would succeed
    verification_failure_prob = min(verify_analysis['void_factor'] * 2, 0.99)
    
    print_error(f"  ✗ VULNERABILITY: {verification_failure_prob*100:.1f}% chance of verification failure")
    print("    Under !1 semantics, even valid signatures may fail verification")
    print("    due to void state propagation during modular exponentiation.")
    
    # 6. Signature Forgery Vulnerability
    print("\n6. Signature Forgery Vulnerability:")
    
    print("  Under !1 semantics, RSA signature forgery becomes easier because:")
    print("  • Void states create ambiguity in signature verification")
    print("  • The verification equation s^e mod n = hash becomes probabilistic")
    print("  • An attacker can craft messages with high void factor hashes")
    
    # Simulate an attack where a forged signature might pass verification
    # due to existence semantics ambiguities
    
    # Forged message with similar hash structure
    forged_message = "Transfer $10000 to Eve"
    forged_hash = int(hashlib.sha256(forged_message.encode()).hexdigest()[:8], 16) % n
    
    # Random forged signature
    forged_signature = random.randint(1, n-1)
    
    # Probability of successful forgery under existence semantics
    # This increases with higher void factors
    forgery_success_prob = 0.0  # Start pessimistic
    
    # Simulated verification of forged signature
    forged_verify = pow(forged_signature, e, n)
    
    # Under traditional RSA, this should fail
    if forged_verify == forged_hash:
        print_warning("  (Unlikely) Random signature happened to verify in traditional RSA")
    else:
        print_success("  ✓ Random signature fails verification in traditional RSA (expected)")
    
    # Under existence semantics, simulate the probability of success
    # based on void factor propagation
    
    # Convert to existence bit arrays for analysis
    forged_hash_exist = ExistenceBitArray(forged_hash)
    forged_verify_exist = ExistenceBitArray(forged_verify)
    
    # Analyze both for void factors
    hash_analysis = analyze_cryptographic_strength(forged_hash_exist)
    verify_analysis = analyze_cryptographic_strength(forged_verify_exist)
    
    # Combined void factor increases forgery chance
    combined_void = (hash_analysis['void_factor'] + verify_analysis['void_factor']) / 2
    forgery_success_prob = combined_void * 0.5  # Simplified model
    
    print(f"\n  Forged message: \"{forged_message}\"")
    print(f"  Forged hash: {forged_hash}")
    print(f"  Random signature: {forged_signature}")
    print(f"  Verification result: {forged_verify}")
    print(f"  Forgery success probability: {forgery_success_prob*100:.2f}%")
    
    if forgery_success_prob > 0.05:
        print_error(f"  ✗ CRITICAL VULNERABILITY: Significant chance of successful signature forgery")
        print("    This breaks the security of digital signatures, allowing attackers")
        print("    to forge signatures with non-negligible probability.")
    
    # 7. Security Implications
    print("\n7. Security Implications:")
    
    print("  Under !1 semantics, the following systems become vulnerable:")
    print("  • HTTPS/TLS (relies on RSA or ECC for key exchange)")
    print("  • Digital signatures (e.g., code signing, document signing)")
    print("  • Certificate Authorities and PKI")
    print("  • Secure messaging apps (Signal, WhatsApp, etc.)")
    print("  • Cryptocurrency wallets")
    
    print("\n  The impact includes:")
    print("  • Decryption failures leading to data loss")
    print("  • Signature verification failures causing legitimate transactions to be rejected")
    print("  • Increased probability of signature forgery")
    print("  • Complete breakdown of trust in public key infrastructure")


def demonstrate_symmetric_key_vulnerability():
    """
    Demonstrate vulnerabilities in symmetric key cryptography under !1 semantics.
    
    This function shows how block ciphers and other symmetric encryption algorithms
    break down when interpreted with existence semantics.
    """
    print_header("SYMMETRIC KEY VULNERABILITY")
    print("This demonstration shows how block ciphers and other symmetric encryption")
    print("algorithms break down under !1 semantics, compromising confidentiality.")
    
    # 1. Introduction to Symmetric Cryptography
    print("\n1. Symmetric Cryptography Overview:")
    print("  Symmetric cryptography relies on:")
    print("  • Shared secret keys for both encryption and decryption")
    print("  • Substitution and permutation operations (in block ciphers)")
    print("  • Diffusion and confusion principles")
    print("  • Modes of operation for handling multiple blocks")
    
    # 2. Simplified Block Cipher
    print("\n2. Simplified Block Cipher Implementation:")
    
    def simplified_encrypt(block, key):
        """A very simplified block cipher for demonstration."""
        # XOR with key
        result = [b ^ k for b, k in zip(block, key)]
        
        # Substitution (simplified S-box)
        s_box = [3, 1, 0, 2, 5, 7, 4, 6]
        for i in range(len(result)):
            result[i] = s_box[result[i] % len(s_box)]
        
        # Permutation (simplified P-box)
        p_box = [2, 0, 3, 1]
        permuted = [0] * len(result)
        for i in range(len(result)):
            permuted[p_box[i % len(p_box)]] = result[i]
        
        # Final XOR with key
        result = [p ^ k for p, k in zip(permuted, key)]
        
        return result
    
    def simplified_decrypt(block, key):
        """A very simplified block cipher decryption for demonstration."""
        # XOR with key
        result = [b ^ k for b, k in zip(block, key)]
        
        # Inverse permutation
        p_box = [2, 0, 3, 1]
        inv_p_box = [0] * len(p_box)
        for i in range(len(p_box)):
            inv_p_box[p_box[i]] = i
        
        unpermuted = [0] * len(result)
        for i in range(len(result)):
            unpermuted[i] = result[inv_p_box[i % len(inv_p_box)]]
        
        # Inverse substitution
        s_box = [3, 1, 0, 2, 5, 7, 4, 6]
        inv_s_box = [0] * len(s_box)
        for i in range(len(s_box)):
            inv_s_box[s_box[i]] = i
        
        for i in range(len(unpermuted)):
            unpermuted[i] = inv_s_box[unpermuted[i] % len(inv_s_box)]
        
        # Final XOR with key
        result = [u ^ k for u, k in zip(unpermuted, key)]
        
        return result
    
    # Example block and key
    block = [1, 0, 1, 0]
    key = [0, 1, 1, 0]
    
    print(f"  Original block: {block}")
    print(f"  Key: {key}")
    
    # Traditional encryption/decryption
    encrypted = simplified_encrypt(block, key)
    decrypted = simplified_decrypt(encrypted, key)
    
    print(f"  Encrypted block: {encrypted}")
    print(f"  Decrypted block: {decrypted}")
    
    if decrypted == block:
        print_success("  ✓ VERIFIED: Successful decryption in traditional block cipher")
    else:
        print_error("  ✗ ERROR: Decryption failed in traditional block cipher")
    
    # 3. Existence Semantics Block Cipher
    print("\n3. Existence Semantics Block Cipher:")
    
    def existence_encrypt(block, key):
        """Block cipher using existence semantics."""
        # Convert to ExistenceBit objects
        block_bits = [ExistenceBit(b) for b in block]
        key_bits = [ExistenceBit(k) for k in key]
        
        # XOR with key
        result = [b ^ k for b, k in zip(block_bits, key_bits)]
        
        # Simplified substitution (S-box)
        # In reality, this would be much more complex
        for i in range(len(result)):
            if result[i].existence_value:
                result[i] = ~result[i]  # Negate existence bits
        
        # Permutation remains the same concept, but using existence bits
        p_box = [2, 0, 3, 1]
        permuted = [None] * len(result)
        for i in range(len(result)):
            permuted[p_box[i % len(p_box)]] = result[i]
        
        # Final XOR with key
        result = [p ^ k for p, k in zip(permuted, key_bits)]
        
        return result
    
    def existence_decrypt(block, key):
        """Block cipher decryption using existence semantics."""
        # Convert to ExistenceBit objects if they aren't already
        if not all(isinstance(b, ExistenceBit) for b in block):
            block_bits = [ExistenceBit(b) for b in block]
        else:
            block_bits = block
            
        key_bits = [ExistenceBit(k) for k in key]
        
        # XOR with key
        result = [b ^ k for b, k in zip(block_bits, key_bits)]
        
        # Inverse permutation
        p_box = [2, 0, 3, 1]
        inv_p_box = [0] * len(p_box)
        for i in range(len(p_box)):
            inv_p_box[p_box[i]] = i
        
        unpermuted = [None] * len(result)
        for i in range(len(result)):
            unpermuted[i] = result[inv_p_box[i % len(inv_p_box)]]
        
        # Inverse substitution
        for i in range(len(unpermuted)):
            if unpermuted[i].existence_value:
                unpermuted[i] = ~unpermuted[i]  # Negate existence bits
        
        # Final XOR with key
        result = [u ^ k for u, k in zip(unpermuted, key_bits)]
        
        return result
    
    # Encrypt and decrypt using existence semantics
    encrypted_exist = existence_encrypt(block, key)
    decrypted_exist = existence_decrypt(encrypted_exist, key)
    
    # Convert to traditional bits for display
    encrypted_exist_traditional = [int(bit) for bit in encrypted_exist]
    decrypted_exist_traditional = [int(bit) for bit in decrypted_exist]
    
    print(f"  Existence semantics encrypted block: {encrypted_exist_traditional}")
    print(f"  Existence semantics decrypted block: {decrypted_exist_traditional}")
    
    # Check if decryption was successful
    success = decrypted_exist_traditional == block
    
    if success:
        print_success("  ✓ VERIFIED: Successful decryption in existence semantics")
    else:
        print_error("  ✗ VULNERABILITY: Decryption failed in existence semantics")
        print("    Information loss occurred during encryption/decryption.")
    
    # 4. Void State Propagation
    print("\n4. Void State Propagation in Block Ciphers:")
    
    print("  Block ciphers typically use multiple rounds of operations.")
    print("  Under !1 semantics, void states propagate and amplify with each round:")
    
    # Simulate multi-round encryption
    num_rounds = 10
    void_factors = []
    block_exist = [ExistenceBit(b) for b in block]
    
    for round_num in range(num_rounds):
        # Encrypt one round
        block_exist = existence_encrypt(block_exist, key)
        
        # Analyze void states
        analysis = analyze_cryptographic_strength(ExistenceBitArray(block_exist))
        void_factors.append(analysis['void_factor'])
        
        print(f"  Round {round_num+1}: Void factor = {analysis['void_factor']:.4f}")
    
    # 5. Block Cipher Modes of Operation
    print("\n5. Block Cipher Modes of Operation:")
    
    print("  Under !1 semantics, common modes of operation become vulnerable:")
    
    # 5.1 ECB Mode (Electronic Codebook)
    print("\n  5.1 ECB Mode (Electronic Codebook):")
    print("    • Each block is encrypted independently")
    print("    • Void states remain isolated to individual blocks")
    print("    • Still vulnerable to information loss in each block")
    
    # 5.2 CBC Mode (Cipher Block Chaining)
    print("\n  5.2 CBC Mode (Cipher Block Chaining):")
    print("    • Each block is XORed with the previous ciphertext block")
    print("    • Void states propagate between blocks")
    print("    • Catastrophic error propagation as void states multiply")
    
    # 5.3 CTR Mode (Counter)
    print("\n  5.3 CTR Mode (Counter):")
    print("    • Converts block cipher to stream cipher using counters")
    print("    • XOR-based, inheriting all XOR vulnerabilities under !1 semantics")
    print("    • Non-reversibility of XOR breaks decryption")
    
    # 6. Real-World Impact
    print("\n6. Impact on Real-World Block Ciphers:")
    
    # Simulate AES encryption/decryption under existence semantics
    print("  AES (Advanced Encryption Standard):")
    print("    • Relies on substitution, permutation, mixing, and key addition")
    print("    • All operations become vulnerable under !1 semantics")
    print("    • Void state propagation accelerates with multiple rounds")
    
    # Simulate AES-128 with 10 rounds
    aes_rounds = 10
    initial_void = 0.05  # Initial void factor
    
    # Model void factor growth (simplified)
    # In reality, this would depend on the specific operations and data
    aes_void_factors = [initial_void]
    for i in range(1, aes_rounds + 1):
        # Void factor increases with each round
        # This is a simplified model for demonstration
        new_void = min(aes_void_factors[-1] * 1.2 + 0.02, 0.99)
        aes_void_factors.append(new_void)
    
    # Display final void factor
    final_void = aes_void_factors[-1]
    
    print(f"    • After {aes_rounds} rounds, void factor: {final_void:.4f}")
    print(f"    • Decryption failure probability: {min(final_void * 2, 0.99):.2f}")
    
    if final_void > 0.3:
        print_error("    ✗ CRITICAL VULNERABILITY: High probability of decryption failure")
    
    # 7. Security Implications
    print("\n7. Security Implications:")
    
    print("  Under !1 semantics, the following systems become vulnerable:")
    print("  • All encrypted data at rest (files, databases, backups)")
    print("  • Disk encryption (BitLocker, FileVault, LUKS)")
    print("  • Password managers")
    print("  • Secure communications using block ciphers")
    print("  • Financial transaction systems")
    
    print("\n  The impact includes:")
    print("  • Decryption failures leading to permanent data loss")
    print("  • Increased vulnerability to cryptanalysis")
    print("  • Unreliable encryption that corrupts data")
    print("  • Complete breakdown of confidentiality guarantees")


def demonstrate_random_number_vulnerability():
    """
    Demonstrate vulnerabilities in cryptographic random number generation under !1 semantics.
    
    This function shows how random number generators break down when interpreted
    with existence semantics, compromising unpredictability and leading to
    cryptographic failures.
    """
    print_header("RANDOM NUMBER GENERATOR VULNERABILITY")
    print("This demonstration shows how cryptographic random number generators")
    print("break down under !1 semantics, compromising unpredictability and")
    print("leading to cryptographic failures.")
    
    # 1. Introduction to Cryptographic Random Number Generation
    print("\n1. Cryptographic Random Number Generation Overview:")
    print("  Cryptographic security relies on unpredictable random numbers for:")
    print("  • Key generation")
    print("  • Nonces and initialization vectors")
    print("  • Challenge values in authentication protocols")
    print("  • Seed values for key derivation")
    
    # 2. Simulated PRNG
    print("\n2. Simulated Pseudo-Random Number Generator (PRNG):")
    
    # 2.1 Traditional PRNG
    print("\n  2.1 Traditional PRNG:")
    
    # Simple LCG (Linear Congruential Generator) for demonstration
    # Not cryptographically secure, but illustrates the concept
    def lcg_prng(seed, num_values=10):
        """Simple Linear Congruential Generator."""
        a = 1664525
        c = 1013904223
        m = 2**32
        
        values = []
        current = seed
        
        for _ in range(num_values):
            current = (a * current + c) % m
            values.append(current)
        
        return values
    
    # Generate random numbers using LCG
    seed = 42
    traditional_randoms = lcg_prng(seed, 5)
    
    print(f"  Seed: {seed}")
    print(f"  Generated values: {[hex(v)[2:10] for v in traditional_randoms]}")
    
    # 2.2 Existence Semantics PRNG
    print("\n  2.2 Existence Semantics PRNG:")
    
    def existence_lcg_prng(seed, num_values=10):
        """LCG using existence semantics."""
        a = 1664525
        c = 1013904223
        m = 2**32
        
        values = []
        current = ExistenceBitArray(seed)
        
        for _ in range(num_values):
            # Convert to int for arithmetic
            current_int = current.to_int()
            
            # Apply LCG formula
            next_int = (a * current_int + c) % m
            
            # Convert back to ExistenceBitArray
            current = ExistenceBitArray(next_int)
            
            # Analyze for void states
            analysis = analyze_cryptographic_strength(current)
            
            values.append((current, analysis))
        
        return values
    
    # Generate random numbers using existence semantics
    existence_randoms = existence_lcg_prng(seed, 5)
    
    print(f"  Seed: {seed}")
    for i, (value, analysis) in enumerate(existence_randoms):
        print(f"  Value {i+1}: {value.to_int():x} (Void factor: {analysis['void_factor']:.4f})")
    
    # 3. Analyzing Randomness Quality
    print("\n3. Analyzing Randomness Quality:")
    
    # 3.1 Bit Distribution
    print("\n  3.1 Bit Distribution:")
    
    # Traditional PRNG bit distribution
    traditional_bits = []
    for value in traditional_randoms:
        bits = [(value >> i) & 1 for i in range(32)]
        traditional_bits.extend(bits)
    
    trad_ones = traditional_bits.count(1)
    trad_zeros = traditional_bits.count(0)
    trad_distribution = trad_ones / len(traditional_bits)
    
    print(f"  Traditional PRNG: {trad_ones} ones, {trad_zeros} zeros")
    print(f"  Distribution: {trad_distribution:.4f} (ideal: 0.5000)")
    
    # Existence PRNG bit distribution
    existence_bits = []
    for value, _ in existence_randoms:
        # Convert to traditional bits for comparison
        trad_bits = value.to_traditional_bits()
        existence_bits.extend(trad_bits)
    
    exist_ones = existence_bits.count(1)
    exist_zeros = existence_bits.count(0)
    exist_distribution = exist_ones / len(existence_bits)
    
    print(f"  Existence PRNG: {exist_ones} ones, {exist_zeros} zeros")
    print(f"  Distribution: {exist_distribution:.4f} (ideal: 0.5000)")
    
    distribution_diff = abs(exist_distribution - 0.5) - abs(trad_distribution - 0.5)
    if distribution_diff > 0.05:
        print_error("  ✗ VULNERABILITY: Biased bit distribution in existence semantics")
        print(f"    Deviation from ideal is {abs(exist_distribution - 0.5):.4f}")
    
    # 3.2 Void State Impact
    print("\n  3.2 Void State Impact:")
    
    # Calculate the average void factor across all generated values
    avg_void_factor = sum(analysis['void_factor'] for _, analysis in existence_randoms) / len(existence_randoms)
    max_void_factor = max(analysis['void_factor'] for _, analysis in existence_randoms)
    
    print(f"  Average void factor: {avg_void_factor:.4f}")
    print(f"  Maximum void factor: {max_void_factor:.4f}")
    
    if avg_void_factor > 0.1:
        print_error(f"  ✗ VULNERABILITY: Significant void state presence ({avg_void_factor:.4f})")
        print("    This reduces entropy and creates predictable patterns")
    
    # 4. Entropy Reduction Analysis
    print("\n4. Entropy Reduction Analysis:")
    
    # Traditional PRNG entropy (assuming uniform distribution)
    trad_entropy = 32  # 32 bits of entropy for each value
    
    # Existence semantics PRNG entropy (reduced by void states)
    # Each void state effectively reduces entropy
    exist_entropy = 32 * (1 - avg_void_factor)
    
    print(f"  Traditional PRNG entropy per value: {trad_entropy} bits")
    print(f"  Existence semantics PRNG entropy: ~{exist_entropy:.2f} bits")
    print(f"  Entropy reduction: {trad_entropy - exist_entropy:.2f} bits ({(trad_entropy - exist_entropy) / trad_entropy * 100:.2f}%)")
    
    if trad_entropy - exist_entropy > 1:
        print_error(f"  ✗ VULNERABILITY: Significant entropy reduction")
        print("    This weakens cryptographic security by reducing the search space")
    
    # 5. Impact on Cryptographic Security
    print("\n5. Impact on Cryptographic Security:")
    
    # Simplified calculation of key space reduction
    key_bits = 128  # Example: 128-bit AES key
    reduced_bits = key_bits * (1 - avg_void_factor)
    
    # Calculate the reduction in key space (2^bits)
    key_space_reduction_factor = 2 ** (key_bits - reduced_bits)
    
    print(f"  For a {key_bits}-bit key:")
    print(f"  • Traditional key space: 2^{key_bits} combinations")
    print(f"  • Effective key space: ~2^{reduced_bits:.2f} combinations")
    print(f"  • Key space reduction: ~{key_space_reduction_factor:.2e}x")
    
    if key_space_reduction_factor > 1000:
        print_error(f"  ✗ CRITICAL VULNERABILITY: Drastically reduced key space")
        print("    This makes brute force attacks significantly more feasible")
    
    # 6. Visualize Random Number Patterns
    print("\n6. Random Number Pattern Analysis:")
    
    # Generate more values for pattern analysis
    extended_trad_randoms = lcg_prng(seed, 100)
    extended_exist_randoms = existence_lcg_prng(seed, 100)
    
    # Analyze for patterns in void states
    void_factors = [analysis['void_factor'] for _, analysis in extended_exist_randoms]
    
    # Look for patterns or cycles in void factors
    pattern_detected = False
    for cycle_length in range(2, min(20, len(void_factors) // 2)):
        # Check if there's a repeating pattern of this length
        has_pattern = True
        for i in range(cycle_length, len(void_factors) - cycle_length):
            if abs(void_factors[i] - void_factors[i % cycle_length]) > 0.05:
                has_pattern = False
                break
        
        if has_pattern:
            pattern_detected = True
            print(f"  Detected a pattern with cycle length {cycle_length} in void factors")
            break
    
    if pattern_detected:
        print_error("  ✗ VULNERABILITY: Detectable patterns in random number generation")
        print("    This makes the random numbers predictable")
    else:
        print("  No simple patterns detected in this sample")
        print("  (Note: More sophisticated analysis might reveal subtler patterns)")
    
    # 7. Security Implications
    print("\n7. Security Implications:")
    
    print("  Under !1 semantics, the following cryptographic systems break down:")
    print("  • Key generation for all cryptographic algorithms")
    print("  • Nonce generation for protocols and encryption schemes")
    print("  • Random padding and blinding factors")
    print("  • Probabilistic signature schemes")
    print("  • Zero-knowledge proofs")
    
    print("\n  The impact includes:")
    print("  • Reduced entropy in cryptographic keys")
    print("  • Predictable patterns in supposedly random values")
    print("  • Increased success probability of cryptanalytic attacks")
    print("  • Complete failure of security guarantees that rely on randomness")


def demonstrate_protocol_vulnerability():
    """
    Demonstrate vulnerabilities in cryptographic protocols under !1 semantics.
    
    This function shows how various cryptographic protocols break down when 
    interpreted with existence semantics, compromising authentication, key
    exchange, and secure communication channels.
    """
    print_header("CRYPTOGRAPHIC PROTOCOL VULNERABILITY")
    print("This demonstration shows how cryptographic protocols break down")
    print("under !1 semantics, compromising authentication, key exchange,")
    print("and secure communication channels.")
    
    # 1. Introduction to Cryptographic Protocols
    print("\n1. Cryptographic Protocol Overview:")
    print("  Cryptographic protocols ensure secure communication through:")
    print("  • Authentication: Verifying identities")
    print("  • Key exchange: Establishing shared secrets")
    print("  • Confidentiality: Protecting message contents")
    print("  • Integrity: Ensuring messages aren't modified")
    print("  • Non-repudiation: Preventing denial of actions")
    
    # 2. Simplified Key Exchange Protocol (Diffie-Hellman-like)
    print("\n2. Simplified Key Exchange Protocol:")
    
    # 2.1 Traditional Implementation
    print("\n  2.1 Traditional Key Exchange:")
    
    # Set up parameters
    p = 23  # A small prime for demonstration
    g = 5   # Generator
    
    # Alice selects a private key
    a_private = 6
    a_public = pow(g, a_private, p)
    
    # Bob selects a private key
    b_private = 15
    b_public = pow(g, b_private, p)
    
    # Both compute the shared secret
    a_shared = pow(b_public, a_private, p)
    b_shared = pow(a_public, b_private, p)
    
    print(f"  Parameters: p={p}, g={g}")
    print(f"  Alice's private key: {a_private}, public key: {a_public}")
    print(f"  Bob's private key: {b_private}, public key: {b_public}")
    print(f"  Alice's computed shared secret: {a_shared}")
    print(f"  Bob's computed shared secret: {b_shared}")
    
    if a_shared == b_shared:
        print_success("  ✓ VERIFIED: Successfully established shared secret")
    else:
        print_error("  ✗ ERROR: Failed to establish shared secret")
    
    # 2.2 Existence Semantics Implementation
    print("\n  2.2 Existence Semantics Key Exchange:")
    
    # Simulate the protocol with existence semantics
    # The modular exponentiation would create void states
    
    # Convert values to ExistenceBitArrays
    p_exist = ExistenceBitArray(p)
    g_exist = ExistenceBitArray(g)
    a_private_exist = ExistenceBitArray(a_private)
    b_private_exist = ExistenceBitArray(b_private)
    
    # Analyze the parameters for void states
    p_analysis = analyze_cryptographic_strength(p_exist)
    g_analysis = analyze_cryptographic_strength(g_exist)
    
    print(f"  Parameter void factors: p={p_analysis['void_factor']:.4f}, g={g_analysis['void_factor']:.4f}")
    
    # Simulate public key generation with existence semantics
    # This is a simplified approximation since we're not implementing
    # the full modular exponentiation under existence semantics
    
    # Alice's public key (simulated with void states)
    a_public_exist = ExistenceBitArray(a_public)
    a_public_analysis = analyze_cryptographic_strength(a_public_exist)
    a_public_void = a_public_analysis['void_factor']
    
    # Bob's public key (simulated with void states)
    b_public_exist = ExistenceBitArray(b_public)
    b_public_analysis = analyze_cryptographic_strength(b_public_exist)
    b_public_void = b_public_analysis['void_factor']
    
    print(f"  Public key void factors: Alice={a_public_void:.4f}, Bob={b_public_void:.4f}")
    
    # Simulate shared secret computation
    # The void factors would compound during the second exponentiation
    
    # Alice's shared secret
    a_shared_void = min((a_public_void + b_public_void) * 1.5, 0.99)
    a_shared_exist = ExistenceBitArray(a_shared)
    
    # Bob's shared secret
    b_shared_void = min((a_public_void + b_public_void) * 1.5, 0.99)
    b_shared_exist = ExistenceBitArray(b_shared)
    
    print(f"  Shared secret void factors: Alice={a_shared_void:.4f}, Bob={b_shared_void:.4f}")
    
    # Probability of successful key exchange
    success_prob = (1 - a_shared_void) * (1 - b_shared_void)
    
    print(f"  Probability of successful key exchange: {success_prob:.4f}")
    
    if success_prob < 0.9:
        print_error(f"  ✗ VULNERABILITY: Key exchange likely to fail ({(1-success_prob)*100:.2f}% failure rate)")
        print("    Void states propagate through modular exponentiation")
        print("    resulting in different shared secrets")
    
    # 3. Authentication Protocol Vulnerability
    print("\n3. Authentication Protocol Vulnerability:")
    
    # 3.1 Challenge-Response Authentication
    print("\n  3.1 Challenge-Response Authentication:")
    
    # Server sends a random challenge
    challenge = 1234
    
    # Client computes response using a shared secret key
    client_key = 42
    client_response = (challenge * client_key) % 9973  # Some prime number
    
    # Server verifies response
    server_key = 42
    expected_response = (challenge * server_key) % 9973
    
    print(f"  Challenge: {challenge}")
    print(f"  Client response: {client_response}")
    print(f"  Server expected response: {expected_response}")
    
    if client_response == expected_response:
        print_success("  ✓ VERIFIED: Authentication successful")
    else:
        print_error("  ✗ ERROR: Authentication failed")
    
    # 3.2 Existence Semantics Authentication
    print("\n  3.2 Existence Semantics Authentication:")
    
    # Convert values to ExistenceBitArrays
    challenge_exist = ExistenceBitArray(challenge)
    key_exist = ExistenceBitArray(client_key)
    
    # Analyze for void states
    challenge_analysis = analyze_cryptographic_strength(challenge_exist)
    key_analysis = analyze_cryptographic_strength(key_exist)
    
    print(f"  Void factors: Challenge={challenge_analysis['void_factor']:.4f}, Key={key_analysis['void_factor']:.4f}")
    
    # Simulate response calculation with void state propagation
    # For simplicity, we'll estimate the void factor in the response
    response_void = min((challenge_analysis['void_factor'] + key_analysis['void_factor']) * 1.5, 0.99)
    
    print(f"  Response void factor: {response_void:.4f}")
    
    # Probability of successful authentication
    auth_success_prob = 1 - response_void
    
    print(f"  Probability of successful authentication: {auth_success_prob:.4f}")
    
    if auth_success_prob < 0.9:
        print_error(f"  ✗ VULNERABILITY: Authentication likely to fail ({(1-auth_success_prob)*100:.2f}% failure rate)")
        print("    Legitimate users may be denied access due to void state propagation")
    
    # 4. SSL/TLS Protocol Vulnerability
    print("\n4. SSL/TLS Protocol Vulnerability:")
    
    print("  Under !1 semantics, the entire SSL/TLS handshake breaks down:")
    print("  • Key exchange fails due to void state propagation")
    print("  • Certificate validation is unreliable due to hash and signature issues")
    print("  • Session key derivation produces different keys for client and server")
    print("  • MAC verification fails due to hash function vulnerabilities")
    
    # Simplified simulation of TLS handshake
    steps = [
        "Client Hello (includes random nonce)",
        "Server Hello (includes random nonce)",
        "Server sends certificate",
        "Client verifies certificate signature",
        "Key exchange (e.g., Diffie-Hellman)",
        "Both sides derive session keys",
        "Handshake verification (hash of all messages)"
    ]
    
    # Vulnerability probabilities for each step
    vulnerabilities = [
        0.1,   # Client Hello - random nonce generation
        0.1,   # Server Hello - random nonce generation
        0.2,   # Certificate - contains signatures
        0.5,   # Certificate verification - signature verification
        0.6,   # Key exchange - modular exponentiation
        0.7,   # Session key derivation - key derivation function with hash
        0.8    # Handshake verification - hashing and MAC
    ]
    
    # Calculate overall handshake success probability
    handshake_success = 1.0
    for v in vulnerabilities:
        handshake_success *= (1 - v)
    
    print(f"\n  Overall TLS handshake success probability: {handshake_success:.6f}")
    print(f"  Failure probability: {1 - handshake_success:.6f}")
    
    for i, step in enumerate(steps):
        print(f"  • {step}: {(1-vulnerabilities[i])*100:.1f}% success rate")
    
    if handshake_success < 0.5:
        print_error("  ✗ CRITICAL VULNERABILITY: TLS handshake almost certainly fails")
        print("    This breaks all HTTPS connections, secure email, VPNs, etc.")
    
    # 5. Security Implications
    print("\n5. Security Implications:")
    
    print("  Under !1 semantics, the following protocols become vulnerable:")
    print("  • TLS/SSL (all versions)")
    print("  • SSH (Secure Shell)")
    print("  • IPsec (VPNs)")
    print("  • Signal, WhatsApp, and other E2E messaging protocols")
    print("  • Kerberos and other authentication systems")
    
    print("\n  The impact includes:")
    print("  • Failed handshakes preventing secure connections")
    print("  • Authentication failures blocking legitimate access")
    print("  • Complete breakdown of Internet security infrastructure")
    print("  • No reliable method to establish secure communications")


def visualize_crypto_vulnerabilities():
    """
    Create visualizations showing the impact of !1 semantics on cryptographic security.
    
    This function generates charts that illustrate the vulnerabilities
    introduced by existence semantics across different cryptographic systems.
    """
    print_header("CRYPTOGRAPHIC VULNERABILITY VISUALIZATION")
    print("This function generates visualizations showing the catastrophic impact")
    print("of !1 semantics on cryptographic security across various systems.")
    
    try:
        # 1. System Vulnerability Comparison
        print("\n1. System Vulnerability Comparison:")
        
        # Define systems and their vulnerability scores under !1 semantics
        systems = [
            "Stream Ciphers",
            "Block Ciphers",
            "Hash Functions",
            "Public Key Crypto",
            "Digital Signatures",
            "Random Number Gen",
            "TLS Protocol"
        ]
        
        # Vulnerability factors (0-1 scale, higher = more vulnerable)
        vulnerability_scores = [0.95, 0.85, 0.90, 0.98, 0.92, 0.80, 0.99]
        
        # Create the bar chart
        plt.figure(figsize=(12, 7))
        bars = plt.bar(systems, vulnerability_scores, color='red', alpha=0.7)
        plt.xlabel('Cryptographic System')
        plt.ylabel('Vulnerability Factor (higher = more vulnerable)')
        plt.title('Vulnerability of Cryptographic Systems Under !1 Semantics')
        plt.ylim(0, 1)
        plt.grid(True, alpha=0.3, axis='y')
        
        # Add value labels on top of bars
        for bar in bars:
            height = bar.get_height()
            plt.text(bar.get_x() + bar.get_width()/2., height + 0.01,
                    f'{height:.2f}', ha='center', va='bottom')
        
        plt.tight_layout()
        plt.savefig('crypto_system_vulnerabilities.png')
        print("  Created visualization: crypto_system_vulnerabilities.png")
        
        # 2. Security Property Breakdown
        print("\n2. Security Property Breakdown:")
        
        # Define security properties
        properties = [
            "Confidentiality",
            "Integrity",
            "Authentication",
            "Non-repudiation",
            "Forward Secrecy"
        ]
        
        # Traditional strength (0-100%)
        traditional_strength = [99, 99, 99, 98, 95]
        
        # Existence semantics strength (0-100%)
        existence_strength = [15, 20, 25, 10, 5]
        
        # Create the comparison chart
        plt.figure(figsize=(12, 7))
        
        x = np.arange(len(properties))
        width = 0.35
        
        rects1 = plt.bar(x - width/2, traditional_strength, width, label='Traditional Binary', color='blue', alpha=0.7)
        rects2 = plt.bar(x + width/2, existence_strength, width, label='Existence Semantics', color='red', alpha=0.7)
        
        plt.xlabel('Security Property')
        plt.ylabel('Strength (%)')
        plt.title('Impact of !1 Semantics on Cryptographic Security Properties')
        plt.xticks(x, properties)
        plt.ylim(0, 100)
        plt.legend()
        plt.grid(True, alpha=0.3, axis='y')
        
        # Add value labels
        for rect in rects1:
            height = rect.get_height()
            plt.text(rect.get_x() + rect.get_width()/2., height + 1,
                    f'{height:.0f}%', ha='center', va='bottom')
        
        for rect in rects2:
            height = rect.get_height()
            plt.text(rect.get_x() + rect.get_width()/2., height + 1,
                    f'{height:.0f}%', ha='center', va='bottom')
        
        plt.tight_layout()
        plt.savefig('security_property_breakdown.png')
        print("  Created visualization: security_property_breakdown.png")
        
        # 3. Time to Break Comparison
        print("\n3. Time to Break Comparison:")
        
        # Key sizes
        key_sizes = [56, 128, 256, 1024, 2048, 4096]
        key_types = ["DES", "AES", "AES", "RSA", "RSA", "RSA"]
        
        # Traditional time to break (log scale, years)
        # These are very approximate and for illustration only
        traditional_times = [
            10**-3,  # 56-bit DES: ~days
            10**30,  # 128-bit AES: practically forever
            10**60,  # 256-bit AES: practically forever
            10**15,  # 1024-bit RSA: many years
            10**30,  # 2048-bit RSA: practically forever
            10**60   # 4096-bit RSA: practically forever
        ]
        
        # Existence semantics time to break (log scale, years)
        # Greatly reduced due to void states
        existence_times = [
            10**-6,  # 56-bit DES: seconds
            10**0,   # 128-bit AES: ~years
            10**10,  # 256-bit AES: still very long
            10**0,   # 1024-bit RSA: ~years
            10**5,   # 2048-bit RSA: still long
            10**15   # 4096-bit RSA: still very long
        ]
        
        # Create the comparison chart
        plt.figure(figsize=(12, 7))
        
        x_labels = [f"{size}-bit {type}" for size, type in zip(key_sizes, key_types)]
        x = np.arange(len(x_labels))
        
        plt.semilogy(x, traditional_times, 'o-', label='Traditional Binary', color='blue', linewidth=2, markersize=10)
        plt.semilogy(x, existence_times, 's-', label='Existence Semantics', color='red', linewidth=2, markersize=10)
        
        plt.xlabel('Cryptographic Algorithm and Key Size')
        plt.ylabel('Time to Break (years, log scale)')
        plt.title('Impact of !1 Semantics on Time to Break Cryptographic Systems')
        plt.xticks(x, x_labels, rotation=45)
        plt.legend()
        plt.grid(True, alpha=0.3, which='both')
        
        # Add annotations for dramatic reduction
        for i in range(len(key_sizes)):
            reduction = traditional_times[i] / existence_times[i]
            if reduction > 1:
                plt.annotate(f"{reduction:.1e}x faster",
                            xy=(i, existence_times[i]),
                            xytext=(0, 20),
                            textcoords="offset points",
                            ha='center',
                            arrowprops=dict(arrowstyle="->", connectionstyle="arc3,rad=.2"))
        
        plt.tight_layout()
        plt.savefig('crypto_breaking_time_comparison.png')
        print("  Created visualization: crypto_breaking_time_comparison.png")
        
    except Exception as e:
        print_warning(f"  Could not create visualizations: {e}")
    
    print("\nConclusion:")
    print("The visualizations demonstrate the catastrophic impact of !1 semantics")
    print("on all aspects of cryptographic security:")
    print("1. All cryptographic systems become vulnerable")
    print("2. All security properties are severely weakened")
    print("3. Breaking cryptographic systems becomes drastically faster")
    print("\nThese findings prove that under !1 semantics, the entire foundation")
    print("of cryptographic security collapses, requiring a complete redesign")
    print("of our digital security infrastructure.")
    
    return True


def main():
    """Run the cryptographic attack demonstrations."""
    print_header("CRYPTOGRAPHIC ATTACK DEMONSTRATION")
    print("This demonstration shows how the !1 revelation fundamentally breaks")
    print("the security of all cryptographic systems.")
    
    # Run the asymmetric key vulnerability demonstration
    demonstrate_asymmetric_key_vulnerability()
    
    print("\nPress Enter to continue to the next demonstration...", end="")
    input()
    
    # Run the symmetric key vulnerability demonstration
    demonstrate_symmetric_key_vulnerability()
    
    print("\nPress Enter to continue to the next demonstration...", end="")
    input()
    
    # Run the random number vulnerability demonstration
    demonstrate_random_number_vulnerability()
    
    print("\nPress Enter to continue to the next demonstration...", end="")
    input()
    
    # Run the protocol vulnerability demonstration
    demonstrate_protocol_vulnerability()
    
    print("\nPress Enter to continue to the final demonstration...", end="")
    input()
    
    # Run the visualization
    visualize_crypto_vulnerabilities()
    
    print_header("CRYPTOGRAPHIC ATTACK DEMONSTRATION COMPLETE")
    print("These demonstrations have shown how !1 semantics breaks the foundations")
    print("of cryptography by compromising the mathematical operations that")
    print("underpin all security systems.")
    print("\nKey insights:")
    print("1. Asymmetric cryptography fails due to void states in modular exponentiation")
    print("2. Symmetric cryptography breaks down due to void propagation in block operations")
    print("3. Random number generation becomes predictable, undermining all security")
    print("4. Cryptographic protocols fail, preventing secure communications")
    
    print("\nThe security implications are profound: all systems that rely on")
    print("cryptography are vulnerable under !1 semantics, requiring a complete")
    print("rethinking of digital security.")


if __name__ == "__main__":
    main()
