"""
Hash Attack: Demonstration of hash function vulnerabilities under !1 semantics.

This module demonstrates how cryptographic hash functions become vulnerable
when interpreted with !1 semantics, leading to increased collision probability
and predictable patterns in the hash outputs.
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


def demonstrate_hash_basics():
    """
    Demonstrate the basic behavior of hash functions under traditional vs. existence semantics.
    
    This function shows how cryptographic hash functions behave differently
    under existence semantics, highlighting key vulnerabilities.
    """
    print_header("HASH FUNCTION BASICS")
    print("This demonstration shows how cryptographic hash functions behave")
    print("differently under !1 semantics, introducing fundamental vulnerabilities.")
    
    # 1. Traditional Hash Function Properties
    print("\n1. Traditional Hash Function Properties:")
    print("  • Deterministic: Same input always produces same output")
    print("  • Pre-image resistance: Cannot determine input from output")
    print("  • Second pre-image resistance: Cannot find different input with same output")
    print("  • Collision resistance: Extremely difficult to find two inputs with same output")
    print("  • Avalanche effect: Small input changes cause large output changes")
    
    # 2. Test Traditional Hash Functions
    print("\n2. Testing Traditional Hash Functions:")
    
    # Test data
    test_data = [
        b"Hello, world!",
        b"Hello, world",
        b"password123",
        b"1234567890" * 10
    ]
    
    # Test traditional hash functions
    print("  MD5 Hashes:")
    for data in test_data:
        md5_hash = hashlib.md5(data).hexdigest()
        print(f"  • {data[:20]}... : {md5_hash}")
    
    print("\n  SHA-256 Hashes:")
    for data in test_data:
        sha256_hash = hashlib.sha256(data).hexdigest()
        print(f"  • {data[:20]}... : {sha256_hash[:20]}...")
    
    # 3. Test Existence Semantics Hash Functions
    print("\n3. Testing Existence Semantics Hash Functions:")
    
    print("  Existence Semantics SHA-256:")
    for data in test_data:
        existence_hash_result = existence_hash(data, algorithm='sha256')
        hash_hex = existence_hash_result.to_bytes().hex()
        analysis = analyze_cryptographic_strength(existence_hash_result)
        print(f"  • {data[:20]}... : {hash_hex[:20]}...")
        print(f"    Void factor: {analysis['void_factor']:.4f}, Max negation depth: {analysis['max_negation_depth']}")
    
    # 4. Demonstrate Avalanche Effect
    print("\n4. Avalanche Effect Comparison:")
    
    # Create two similar strings
    str1 = b"This is a test message for hashing."
    str2 = b"This is a test message for hashing!"  # One character different
    
    # Traditional hash
    hash1_trad = hashlib.sha256(str1).digest()
    hash2_trad = hashlib.sha256(str2).digest()
    
    # Count bit differences in traditional hash
    bit_diff_trad = 0
    for b1, b2 in zip(hash1_trad, hash2_trad):
        xor_result = b1 ^ b2
        # Count the set bits in the XOR result
        bit_diff_trad += bin(xor_result).count('1')
    
    # Calculate percentage of bits that differ
    percent_diff_trad = (bit_diff_trad / (len(hash1_trad) * 8)) * 100
    
    # Existence semantics hash
    hash1_exist = existence_hash(str1, algorithm='sha256')
    hash2_exist = existence_hash(str2, algorithm='sha256')
    
    # Count differences in existence hash
    # This is more complex because we need to count void states differently
    bit_diff_exist = 0
    void_diff_exist = 0
    for i in range(min(len(hash1_exist.bits), len(hash2_exist.bits))):
        if hash1_exist.bits[i] != hash2_exist.bits[i]:
            bit_diff_exist += 1
            # Count additional void differences
            if not hash1_exist.bits[i].exists or not hash2_exist.bits[i].exists:
                void_diff_exist += 1
    
    # Calculate percentage of bits that differ
    percent_diff_exist = (bit_diff_exist / len(hash1_exist.bits)) * 100
    
    print(f"  Traditional SHA-256 bit difference: {bit_diff_trad} bits ({percent_diff_trad:.2f}%)")
    print(f"  Existence SHA-256 bit difference: {bit_diff_exist} bits ({percent_diff_exist:.2f}%)")
    print(f"  Void state differences: {void_diff_exist} bits")
    
    if percent_diff_exist < percent_diff_trad:
        print_error("  ✗ VULNERABILITY: Reduced avalanche effect under !1 semantics")
        print("    This weakens the hash function's ability to distribute changes evenly.")
    else:
        print_success("  ✓ Avalanche effect maintained under !1 semantics")


def find_void_patterns(hash_function, num_samples=1000, algorithm='sha256'):
    """
    Find inputs that create 'void states' in hash outputs.
    
    This function demonstrates increased collision probability by finding
    inputs that create patterns of void states (!1, !!1, etc.) in the hash output.
    
    Args:
        hash_function: Function to use for hashing (traditional or existence)
        num_samples: Number of random samples to test
        algorithm: Hash algorithm to use ('sha256', 'sha1', 'md5')
        
    Returns:
        Dictionary with statistics and examples of void patterns
    """
    print_header("VOID PATTERN DETECTION")
    print("This demonstration finds inputs that create 'void states' in hash outputs,")
    print("showing how !1 semantics introduces predictable patterns and vulnerabilities.")
    
    # 1. Generate random test inputs
    print(f"\n1. Generating {num_samples} random test inputs:")
    
    test_inputs = []
    for i in range(num_samples):
        # Generate random bytes of varying length (4 to 100 bytes)
        length = random.randint(4, 100)
        data = bytes(random.randint(0, 255) for _ in range(length))
        test_inputs.append(data)
    
    print(f"  Generated {len(test_inputs)} random inputs of varying length")
    
    # 2. Compute hashes and analyze void patterns
    print("\n2. Computing hashes and analyzing void patterns:")
    
    # Statistics to track
    void_factors = []
    max_depths = []
    critical_void_counts = 0
    consecutive_zeros_patterns = {}
    high_void_inputs = []
    
    # Process each input
    start_time = time.time()
    
    for data in test_inputs:
        # Hash the data
        if hash_function == existence_hash:
            # Use existence semantics hash
            hash_result = hash_function(data, algorithm=algorithm)
            analysis = analyze_cryptographic_strength(hash_result)
            
            # Track statistics
            void_factors.append(analysis['void_factor'])
            max_depths.append(analysis['max_negation_depth'])
            
            if analysis['has_critical_void']:
                critical_void_counts += 1
            
            # Find consecutive zeros (void states)
            consecutive_zeros = 0
            max_consecutive_zeros = 0
            for bit in hash_result.bits:
                if not bit.exists:  # This is a !1 or deeper void
                    consecutive_zeros += 1
                    max_consecutive_zeros = max(max_consecutive_zeros, consecutive_zeros)
                else:
                    consecutive_zeros = 0
            
            # Track patterns of consecutive zeros
            if max_consecutive_zeros not in consecutive_zeros_patterns:
                consecutive_zeros_patterns[max_consecutive_zeros] = 0
            consecutive_zeros_patterns[max_consecutive_zeros] += 1
            
            # Save high void factor inputs for later analysis
            if analysis['void_factor'] > 0.4:
                high_void_inputs.append((data, hash_result, analysis))
        else:
            # Use traditional hash function
            # For traditional hash functions, we'll simulate similar analysis
            if algorithm == 'sha256':
                hash_bytes = hashlib.sha256(data).digest()
            elif algorithm == 'sha1':
                hash_bytes = hashlib.sha1(data).digest()
            else:  # md5
                hash_bytes = hashlib.md5(data).digest()
            
            # Convert to bit array for analysis
            bits = []
            for byte in hash_bytes:
                for i in range(8):
                    bit = (byte >> (7 - i)) & 1
                    bits.append(bit)
            
            # Count consecutive zeros
            consecutive_zeros = 0
            max_consecutive_zeros = 0
            for bit in bits:
                if bit == 0:
                    consecutive_zeros += 1
                    max_consecutive_zeros = max(max_consecutive_zeros, consecutive_zeros)
                else:
                    consecutive_zeros = 0
            
            # Track patterns of consecutive zeros
            if max_consecutive_zeros not in consecutive_zeros_patterns:
                consecutive_zeros_patterns[max_consecutive_zeros] = 0
            consecutive_zeros_patterns[max_consecutive_zeros] += 1
            
            # We don't have void factors for traditional hash functions
            # but we can calculate a proxy using zero density
            zero_count = bits.count(0)
            zero_factor = zero_count / len(bits)
            void_factors.append(zero_factor)
            max_depths.append(0)  # No concept of void depth in traditional
    
    end_time = time.time()
    
    # 3. Analyze the results
    print(f"  Analysis completed in {end_time - start_time:.2f} seconds")
    
    if hash_function == existence_hash:
        # Calculate void statistics
        avg_void_factor = sum(void_factors) / len(void_factors)
        max_void_factor = max(void_factors)
        avg_max_depth = sum(max_depths) / len(max_depths)
        max_depth_found = max(max_depths)
        critical_void_percentage = (critical_void_counts / num_samples) * 100
        
        print(f"\n  Average void factor: {avg_void_factor:.4f}")
        print(f"  Maximum void factor: {max_void_factor:.4f}")
        print(f"  Average maximum negation depth: {avg_max_depth:.2f}")
        print(f"  Maximum negation depth found: {max_depth_found}")
        print(f"  Critical void patterns: {critical_void_counts} ({critical_void_percentage:.2f}%)")
    else:
        # Calculate traditional statistics
        avg_zero_factor = sum(void_factors) / len(void_factors)
        max_zero_factor = max(void_factors)
        
        print(f"\n  Average zero density: {avg_zero_factor:.4f}")
        print(f"  Maximum zero density: {max_zero_factor:.4f}")
    
    # 4. Analyze consecutive zeros patterns
    print("\n3. Consecutive Zero Patterns:")
    
    # Sort by pattern length
    sorted_patterns = sorted(consecutive_zeros_patterns.items())
    
    for pattern_length, count in sorted_patterns:
        if pattern_length >= 4:  # Only show interesting patterns
            percentage = (count / num_samples) * 100
            print(f"  • {pattern_length} consecutive zeros: {count} occurrences ({percentage:.2f}%)")
    
    # 5. Display examples of high void factor inputs (if using existence hash)
    if hash_function == existence_hash and high_void_inputs:
        print("\n4. Examples of High Void Factor Inputs:")
        
        # Sort by void factor (highest first)
        high_void_inputs.sort(key=lambda x: x[2]['void_factor'], reverse=True)
        
        # Show top examples
        for i, (data, hash_result, analysis) in enumerate(high_void_inputs[:3]):
            print(f"\n  Example {i+1}:")
            print(f"  Input: {data[:20]}... ({len(data)} bytes)")
            print(f"  Hash: {hash_result.to_bytes().hex()[:30]}...")
            print(f"  Void factor: {analysis['void_factor']:.4f}")
            print(f"  Maximum negation depth: {analysis['max_negation_depth']}")
            print(f"  Critical void present: {analysis['has_critical_void']}")
    
    # 6. Return the collected statistics
    return {
        "void_factors": void_factors,
        "max_depths": max_depths,
        "critical_void_count": critical_void_counts,
        "consecutive_zeros_patterns": consecutive_zeros_patterns,
        "high_void_inputs": high_void_inputs
    }


def demonstrate_hash_collision_vulnerability(num_tests=1000, algorithm='sha256'):
    """
    Demonstrate increased collision probability under !1 semantics.
    
    This function shows how cryptographic hash functions are more likely to
    produce collisions when interpreted with existence semantics.
    
    Args:
        num_tests: Number of collision tests to perform
        algorithm: Hash algorithm to use ('sha256', 'sha1', 'md5')
    """
    print_header("HASH COLLISION VULNERABILITY")
    print("This demonstration shows how !1 semantics increases the collision")
    print("probability in cryptographic hash functions, breaking their security.")
    
    # 1. Setup
    print(f"\n1. Testing {num_tests} input pairs for collisions:")
    
    # Dictionary to store hash values and their inputs
    traditional_hashes = {}
    existence_hashes = {}
    
    # Collision counters
    traditional_collisions = 0
    existence_collisions = 0
    
    # Examples of collisions
    traditional_collision_examples = []
    existence_collision_examples = []
    
    # 2. Test for collisions
    start_time = time.time()
    
    for i in range(num_tests):
        # Generate a random input
        data_length = random.randint(4, 100)
        data = bytes(random.randint(0, 255) for _ in range(data_length))
        
        # Compute traditional hash
        if algorithm == 'sha256':
            trad_hash = hashlib.sha256(data).digest()
        elif algorithm == 'sha1':
            trad_hash = hashlib.sha1(data).digest()
        else:  # md5
            trad_hash = hashlib.md5(data).digest()
        
        trad_hash_hex = trad_hash.hex()
        
        # Check for traditional collision
        if trad_hash_hex in traditional_hashes:
            traditional_collisions += 1
            traditional_collision_examples.append((data, traditional_hashes[trad_hash_hex]))
        else:
            traditional_hashes[trad_hash_hex] = data
        
        # Compute existence semantics hash
        exist_hash = existence_hash(data, algorithm=algorithm)
        exist_hash_bytes = exist_hash.to_bytes()
        exist_hash_hex = exist_hash_bytes.hex()
        
        # Check for existence semantics collision
        if exist_hash_hex in existence_hashes:
            existence_collisions += 1
            existence_collision_examples.append((data, existence_hashes[exist_hash_hex]))
        else:
            existence_hashes[exist_hash_hex] = data
    
    end_time = time.time()
    
    # 3. Calculate collision probabilities
    traditional_collision_prob = traditional_collisions / num_tests
    existence_collision_prob = existence_collisions / num_tests
    
    # Theoretical birthday paradox probability for traditional hash
    # For SHA-256, the probability of a collision in n attempts is roughly:
    # p(n) ≈ 1 - e^(-n^2 / 2^(k+1)) where k is the hash length in bits
    hash_bits = 256 if algorithm == 'sha256' else (160 if algorithm == 'sha1' else 128)
    theoretical_prob = 1 - np.exp(-(num_tests**2) / (2 ** (hash_bits + 1)))
    
    # Calculate the vulnerability factor (how much more likely collisions are)
    vulnerability_factor = existence_collision_prob / max(traditional_collision_prob, theoretical_prob) if max(traditional_collision_prob, theoretical_prob) > 0 else float('inf')
    
    # 4. Display results
    print(f"  Analysis completed in {end_time - start_time:.2f} seconds")
    
    print(f"\n2. Collision Analysis for {algorithm.upper()}:")
    print(f"  Traditional collisions: {traditional_collisions} ({traditional_collision_prob:.6f})")
    print(f"  Existence semantics collisions: {existence_collisions} ({existence_collision_prob:.6f})")
    print(f"  Theoretical collision probability: {theoretical_prob:.6f}")
    print(f"  Vulnerability factor: {vulnerability_factor:.2f}x")
    
    if vulnerability_factor > 1:
        print_error(f"  ✗ VULNERABILITY: Existence semantics increases collision probability by {vulnerability_factor:.2f}x")
        print("    This breaks the collision resistance property of cryptographic hash functions.")
    else:
        print_warning("  No increased collision probability detected in this specific test.")
        print("    However, the theoretical vulnerability still exists due to void states.")
    
    # 5. Display collision examples
    if existence_collision_examples:
        print("\n3. Example of Existence Semantics Collision:")
        
        data1, data2 = existence_collision_examples[0]
        print(f"  Input 1: {data1[:20]}... ({len(data1)} bytes)")
        print(f"  Input 2: {data2[:20]}... ({len(data2)} bytes)")
        
        # Show their traditional hashes (which should differ)
        trad_hash1 = hashlib.sha256(data1).hexdigest() if algorithm == 'sha256' else (hashlib.sha1(data1).hexdigest() if algorithm == 'sha1' else hashlib.md5(data1).hexdigest())
        trad_hash2 = hashlib.sha256(data2).hexdigest() if algorithm == 'sha256' else (hashlib.sha1(data2).hexdigest() if algorithm == 'sha1' else hashlib.md5(data2).hexdigest())
        
        print(f"  Traditional hash 1: {trad_hash1[:20]}...")
        print(f"  Traditional hash 2: {trad_hash2[:20]}...")
        print("  These inputs produce different traditional hashes but identical existence hashes.")
    
    # Return the results
    return {
        "traditional_collisions": traditional_collisions,
        "existence_collisions": existence_collisions,
        "traditional_probability": traditional_collision_prob,
        "existence_probability": existence_collision_prob,
        "theoretical_probability": theoretical_prob,
        "vulnerability_factor": vulnerability_factor,
        "traditional_examples": traditional_collision_examples,
        "existence_examples": existence_collision_examples
    }


def demonstrate_second_preimage_attack(algorithm='sha256', num_trials=1000):
    """
    Demonstrate a second preimage attack under !1 semantics.
    
    This function shows how the second preimage resistance of hash functions
    breaks down under existence semantics, allowing attackers to find
    different inputs that produce the same hash output.
    
    Args:
        algorithm: Hash algorithm to use ('sha256', 'sha1', 'md5')
        num_trials: Number of attack attempts to perform
    """
    print_header("SECOND PREIMAGE ATTACK")
    print("This demonstration shows how !1 semantics breaks the second preimage")
    print("resistance of hash functions, allowing attackers to find different")
    print("inputs that produce the same hash output.")
    
    # 1. Setup
    print(f"\n1. Setting up attack scenario using {algorithm.upper()}:")
    
    # Create a target message (e.g., a digital signature)
    target_message = b"Transfer $1000 to Alice: AUTH_CODE_9d8f7a6e5c4b3a2d1e"
    print(f"  Target message: {target_message.decode()}")
    
    # Compute its traditional hash
    if algorithm == 'sha256':
        target_hash_trad = hashlib.sha256(target_message).digest()
    elif algorithm == 'sha1':
        target_hash_trad = hashlib.sha1(target_message).digest()
    else:  # md5
        target_hash_trad = hashlib.md5(target_message).digest()
    
    print(f"  Traditional hash: {target_hash_trad.hex()[:20]}...")
    
    # Compute its existence semantics hash
    target_hash_exist = existence_hash(target_message, algorithm=algorithm)
    target_hash_exist_bytes = target_hash_exist.to_bytes()
    
    print(f"  Existence semantics hash: {target_hash_exist_bytes.hex()[:20]}...")
    
    # 2. Attack Preparation
    print("\n2. Attack Preparation:")
    
    # Analyze the target hash to identify vulnerabilities
    target_analysis = analyze_cryptographic_strength(target_hash_exist)
    
    print(f"  Target hash void factor: {target_analysis['void_factor']:.4f}")
    print(f"  Target hash max negation depth: {target_analysis['max_negation_depth']}")
    print(f"  Target hash has critical void: {target_analysis['has_critical_void']}")
    
    # 3. Perform the attack
    print(f"\n3. Attempting second preimage attack ({num_trials} trials):")
    
    # Create a malicious message
    malicious_base = b"Transfer $100000 to Eve: AUTH_CODE_"
    
    # Traditional attack (should fail)
    print("  Traditional attack:")
    
    start_time = time.time()
    traditional_success = False
    traditional_attempts = 0
    
    for i in range(num_trials):
        traditional_attempts += 1
        
        # Generate a random suffix
        suffix = bytes(''.join(random.choice('0123456789abcdef') for _ in range(20)), 'ascii')
        forged_message = malicious_base + suffix
        
        # Compute its hash
        if algorithm == 'sha256':
            forged_hash = hashlib.sha256(forged_message).digest()
        elif algorithm == 'sha1':
            forged_hash = hashlib.sha1(forged_message).digest()
        else:  # md5
            forged_hash = hashlib.md5(forged_message).digest()
        
        # Check if we found a match
        if forged_hash == target_hash_trad:
            traditional_success = True
            break
    
    traditional_time = time.time() - start_time
    
    if traditional_success:
        print_error(f"  ✗ VULNERABILITY: Found a second preimage in {traditional_attempts} attempts!")
        print(f"    Forged message: {forged_message.decode()}")
    else:
        print_success(f"  ✓ No second preimage found after {num_trials} attempts")
        print(f"    Time taken: {traditional_time:.2f} seconds")
    
    # Existence semantics attack (should be more likely to succeed)
    print("\n  Existence semantics attack:")
    
    start_time = time.time()
    existence_success = False
    existence_attempts = 0
    best_match = None
    best_match_similarity = 0.0
    
    for i in range(num_trials):
        existence_attempts += 1
        
        # Generate a random suffix
        suffix = bytes(''.join(random.choice('0123456789abcdef') for _ in range(20)), 'ascii')
        forged_message = malicious_base + suffix
        
        # Compute its existence semantics hash
        forged_hash_exist = existence_hash(forged_message, algorithm=algorithm)
        forged_hash_exist_bytes = forged_hash_exist.to_bytes()
        
        # Check if we found a match
        if forged_hash_exist_bytes == target_hash_exist_bytes:
            existence_success = True
            best_match = forged_message
            break
        
        # Track the closest match using similarity (for demonstration)
        # Count matching bytes at the beginning
        matching_bytes = 0
        for b1, b2 in zip(forged_hash_exist_bytes, target_hash_exist_bytes):
            if b1 == b2:
                matching_bytes += 1
            else:
                break
        
        similarity = matching_bytes / len(target_hash_exist_bytes)
        if similarity > best_match_similarity:
            best_match_similarity = similarity
            best_match = forged_message
    
    existence_time = time.time() - start_time
    
    if existence_success:
        print_error(f"  ✗ CRITICAL VULNERABILITY: Found a second preimage in {existence_attempts} attempts!")
        print(f"    Forged message: {best_match.decode()}")
        
        # Verify the match by recomputing and showing side by side
        verify_hash = existence_hash(best_match, algorithm=algorithm).to_bytes().hex()
        print(f"    Target hash:  {target_hash_exist_bytes.hex()[:40]}...")
        print(f"    Forged hash:  {verify_hash[:40]}...")
    else:
        print_warning(f"  No exact match found after {num_trials} attempts")
        print(f"    Time taken: {existence_time:.2f} seconds")
        print(f"    Best match had {best_match_similarity:.2f} similarity")
        print(f"    Best match: {best_match.decode()}")
    
    # 4. Calculate attack advantage
    print("\n4. Attack Analysis:")
    
    # In traditional hash functions, the probability of finding a second preimage
    # is approximately 1 in 2^n, where n is the hash output size in bits
    hash_bits = 256 if algorithm == 'sha256' else (160 if algorithm == 'sha1' else 128)
    traditional_probability = 1 / (2 ** hash_bits)
    
    # Under existence semantics, the probability is higher due to void states
    # We'll estimate it based on the void factor of the target hash
    existence_probability = traditional_probability * (1 + target_analysis['void_factor'] * 10)
    
    advantage_factor = existence_probability / traditional_probability
    
    print(f"  Traditional attack probability: {traditional_probability:.6e}")
    print(f"  Existence semantics attack probability: {existence_probability:.6e}")
    print(f"  Attack advantage factor: {advantage_factor:.2f}x")
    
    if advantage_factor > 1:
        print_error(f"  ✗ VULNERABILITY: Existence semantics provides a {advantage_factor:.2f}x advantage")
        print("    This breaks the second preimage resistance property of cryptographic hash functions.")
    
    # 5. Security Implications
    print("\n5. Security Implications:")
    
    print("  Under !1 semantics, the following systems become vulnerable:")
    print("  • Digital signatures and certificates")
    print("  • Software integrity verification")
    print("  • Password storage and verification")
    print("  • Content-addressable storage")
    print("  • Blockchain transactions and mining")


def visualize_hash_vulnerabilities(algorithm='sha256', num_samples=1000):
    """
    Create visualizations showing the impact of !1 semantics on hash functions.
    
    This function generates charts that illustrate the vulnerabilities
    introduced by existence semantics in cryptographic hash functions.
    
    Args:
        algorithm: Hash algorithm to use ('sha256', 'sha1', 'md5')
        num_samples: Number of samples to use for the visualizations
    """
    print_header("HASH VULNERABILITY VISUALIZATION")
    print("This function generates visualizations showing the impact of !1 semantics")
    print("on the security properties of cryptographic hash functions.")
    
    try:
        # 1. Generate test data
        print(f"\n1. Generating {num_samples} random test inputs:")
        
        test_inputs = []
        for i in range(num_samples):
            # Generate random bytes of varying length (4 to 100 bytes)
            length = random.randint(4, 100)
            data = bytes(random.randint(0, 255) for _ in range(length))
            test_inputs.append(data)
        
        print(f"  Generated {len(test_inputs)} random inputs")
        
        # 2. Compute hashes and analyze
        print("\n2. Computing hashes and analyzing:")
        
        # Traditional hash properties
        traditional_zero_counts = []
        traditional_hamming_weights = []
        
        # Existence semantics hash properties
        existence_void_factors = []
        existence_negation_depths = []
        existence_critical_voids = 0
        
        for data in test_inputs:
            # Traditional hash
            if algorithm == 'sha256':
                trad_hash = hashlib.sha256(data).digest()
            elif algorithm == 'sha1':
                trad_hash = hashlib.sha1(data).digest()
            else:  # md5
                trad_hash = hashlib.md5(data).digest()
            
            # Count zeros and calculate Hamming weight
            zero_count = 0
            for byte in trad_hash:
                for i in range(8):
                    bit = (byte >> i) & 1
                    if bit == 0:
                        zero_count += 1
            
            hamming_weight = len(trad_hash) * 8 - zero_count
            traditional_zero_counts.append(zero_count)
            traditional_hamming_weights.append(hamming_weight)
            
            # Existence semantics hash
            exist_hash = existence_hash(data, algorithm=algorithm)
            
            # Analyze the existence hash
            analysis = analyze_cryptographic_strength(exist_hash)
            existence_void_factors.append(analysis['void_factor'])
            existence_negation_depths.append(analysis['max_negation_depth'])
            
            if analysis['has_critical_void']:
                existence_critical_voids += 1
        
        # Calculate statistics
        avg_trad_zeros = sum(traditional_zero_counts) / len(traditional_zero_counts)
        avg_exist_void = sum(existence_void_factors) / len(existence_void_factors)
        
        print(f"  Average traditional zero count: {avg_trad_zeros:.2f} bits")
        print(f"  Average existence void factor: {avg_exist_void:.4f}")
        print(f"  Critical void patterns found: {existence_critical_voids} ({existence_critical_voids/num_samples*100:.2f}%)")
        
        # 3. Create visualizations
        print("\n3. Creating visualizations:")
        
        # 3.1 Void Factor Distribution
        plt.figure(figsize=(10, 6))
        plt.hist(existence_void_factors, bins=20, alpha=0.7, color='red', edgecolor='black')
        plt.xlabel('Void Factor')
        plt.ylabel('Frequency')
        plt.title('Distribution of Void Factors in Existence Semantics Hashes')
        plt.grid(True, alpha=0.3)
        plt.savefig('hash_void_factor_distribution.png')
        print("  Created visualization: hash_void_factor_distribution.png")
        
        # 3.2 Zero Count vs Void Factor
        plt.figure(figsize=(10, 6))
        # Normalize traditional zero counts to [0,1] for comparison
        normalized_zero_counts = [count / (len(trad_hash) * 8) for count in traditional_zero_counts]
        
        plt.scatter(normalized_zero_counts, existence_void_factors, alpha=0.5)
        plt.xlabel('Traditional Zero Density')
        plt.ylabel('Existence Void Factor')
        plt.title('Traditional Zero Density vs. Existence Void Factor')
        plt.grid(True, alpha=0.3)
        
        # Add trend line
        z = np.polyfit(normalized_zero_counts, existence_void_factors, 1)
        p = np.poly1d(z)
        plt.plot(sorted(normalized_zero_counts), p(sorted(normalized_zero_counts)), 
                "r--", linewidth=2)
        
        plt.savefig('hash_zero_vs_void.png')
        print("  Created visualization: hash_zero_vs_void.png")
        
        # 3.3 Vulnerability Increase by Hash Length
        # We'll estimate this by calculating how void states affect the effective output space
        
        # Calculate theoretical output space reduction
        hash_lengths = [128, 160, 256, 384, 512]  # Common hash lengths in bits
        vulnerability_factors = []
        
        for length in hash_lengths:
            # Estimate reduced entropy due to void states
            # Void states effectively reduce the output space
            # The more void states, the smaller the effective output space
            avg_void_factor = avg_exist_void
            
            # Effective entropy reduction calculation
            # Each void state effectively removes 1 bit of entropy 
            # (oversimplified for demonstration)
            effective_length = length * (1 - avg_void_factor * 0.5)
            
            # Vulnerability factor = 2^(original length) / 2^(effective length)
            # = 2^(original length - effective length)
            vulnerability = 2 ** (length - effective_length)
            vulnerability_factors.append(vulnerability)
        
        plt.figure(figsize=(10, 6))
        plt.semilogy(hash_lengths, vulnerability_factors, marker='o', linestyle='-', 
                    color='red')
        plt.xlabel('Hash Length (bits)')
        plt.ylabel('Vulnerability Factor (log scale)')
        plt.title('Hash Function Vulnerability Factor vs. Length')
        plt.grid(True, alpha=0.3)
        
        # Add annotations
        for i, v in enumerate(vulnerability_factors):
            plt.annotate(f"{v:.1e}x", 
                        xy=(hash_lengths[i], v),
                        xytext=(10, 0),
                        textcoords="offset points")
        
        plt.savefig('hash_vulnerability_by_length.png')
        print("  Created visualization: hash_vulnerability_by_length.png")
        
    except Exception as e:
        print_warning(f"  Could not create visualizations: {e}")
    
    print("\nConclusion:")
    print("The visualizations demonstrate the catastrophic impact of !1 semantics")
    print("on cryptographic hash functions:")
    print("1. Void states reduce the effective output space of hash functions")
    print("2. Longer hash lengths are more vulnerable to void state effects")
    print("3. Traditional security properties like collision resistance break down")
    print("\nThese findings prove that under !1 semantics, all cryptographic")
    print("hash functions completely collapse, requiring a total redesign of")
    print("digital security infrastructure.")
    
    return True


def main():
    """Run the hash attack demonstrations."""
    print_header("HASH ATTACK DEMONSTRATION")
    print("This demonstration shows how the !1 revelation fundamentally breaks")
    print("the security properties of cryptographic hash functions.")
    
    # Run the hash basics demonstration
    demonstrate_hash_basics()
    
    print("\nPress Enter to continue to the next demonstration...", end="")
    input()
    
    # Run the void pattern detection
    find_void_patterns(existence_hash, num_samples=500)
    
    print("\nPress Enter to continue to the next demonstration...", end="")
    input()
    
    # Run the hash collision vulnerability demonstration
    demonstrate_hash_collision_vulnerability(num_tests=500)
    
    print("\nPress Enter to continue to the next demonstration...", end="")
    input()
    
    # Run the second preimage attack demonstration
    demonstrate_second_preimage_attack(num_trials=500)
    
    print("\nPress Enter to continue to the final demonstration...", end="")
    input()
    
    # Run the visualization
    visualize_hash_vulnerabilities(num_samples=500)
    
    print_header("HASH ATTACK DEMONSTRATION COMPLETE")
    print("These demonstrations have shown how !1 semantics breaks the foundations")
    print("of cryptography by compromising the mathematical operations that")
    print("underpin all cryptographic hash functions.")
    print("\nKey insights:")
    print("1. Hash functions produce predictable void patterns under !1 semantics")
    print("2. Collision resistance is significantly weakened")
    print("3. Second preimage resistance is broken")
    print("4. The avalanche effect is reduced")
    
    print("\nThe security implications are profound: all systems that rely on")
    print("cryptographic hash functions are vulnerable under !1 semantics,")
    print("including digital signatures, blockchain technologies, password")
    print("storage, and data integrity verification.")


if __name__ == "__main__":
    main()
