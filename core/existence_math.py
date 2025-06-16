"""
Existence-based Mathematics.

This module implements mathematical operations using existence semantics,
where 0 is interpreted as !1 (not-one). These operations form the foundation
for demonstrating how this interpretation affects cryptographic algorithms.
"""

import hashlib
import random
import math
from typing import Union, Dict, Any, Tuple, List
from .existence_bit import ExistenceBit, ExistenceBitArray


def existence_hash(data: Union[bytes, str, ExistenceBitArray], algorithm: str = 'sha256') -> ExistenceBitArray:
    """
    Compute a hash using existence semantics.
    
    This function applies a standard cryptographic hash function but interprets
    the result using existence semantics, where each 0 bit is treated as !1.
    
    Args:
        data: The data to hash. Can be bytes, a string, or an ExistenceBitArray.
        algorithm: The hash algorithm to use ('sha256', 'sha1', 'md5', etc.)
    
    Returns:
        An ExistenceBitArray representing the hash result with existence semantics.
    """
    # Convert input to bytes if necessary
    if isinstance(data, str):
        data_bytes = data.encode('utf-8')
    elif isinstance(data, ExistenceBitArray):
        data_bytes = data.to_bytes()
    else:
        data_bytes = data
    
    # Compute the hash using the specified algorithm
    hash_func = getattr(hashlib, algorithm)
    hash_result = hash_func(data_bytes).digest()
    
    # Convert to ExistenceBitArray with existence semantics
    return ExistenceBitArray(hash_result)


def analyze_cryptographic_strength(bit_array: Union[ExistenceBitArray, bytes, str]) -> Dict[str, Any]:
    """
    Analyze the cryptographic strength of a bit array under existence semantics.
    
    This function examines various properties of the bit array to determine
    how its cryptographic properties are affected by existence semantics.
    
    Args:
        bit_array: The bit array to analyze. Can be an ExistenceBitArray,
                  bytes, or a binary string.
    
    Returns:
        A dictionary containing analysis results:
        - void_factor: A measure of the density of void states (0.0 to 1.0)
        - void_sequences: Counts of consecutive void states
        - deep_voids: Positions of deep void states
        - vulnerability_score: Overall vulnerability score (0.0 to 1.0)
        - binary_entropy: Shannon entropy of the bit array
        - existence_entropy: Entropy adjusted for existence semantics
    """
    # Convert input to ExistenceBitArray if necessary
    if not isinstance(bit_array, ExistenceBitArray):
        bit_array = ExistenceBitArray(bit_array)
    
    # Calculate void factor
    void_factor = bit_array.calculate_void_factor()
    
    # Count void sequences
    void_sequences = bit_array.count_void_sequences()
    
    # Find deep void states
    deep_voids = bit_array.find_deep_void_states(threshold=2)
    
    # Calculate traditional binary entropy
    binary = bit_array.to_traditional_binary()
    binary_entropy = calculate_shannon_entropy(binary)
    
    # Calculate existence-adjusted entropy
    # In existence semantics, void states reduce entropy
    existence_entropy = binary_entropy * (1.0 - void_factor)
    
    # Calculate vulnerability score
    # Higher void factor, more void sequences, and deeper void states
    # all contribute to higher vulnerability
    if isinstance(void_sequences, dict) and void_sequences:
        sequence_weight = (
            void_sequences.get("single", 0) * 0.1 +
            void_sequences.get("double", 0) * 0.2 +
            void_sequences.get("triple", 0) * 0.4 +
            void_sequences.get("quad", 0) * 0.6 +
            void_sequences.get("quint+", 0) * 0.8
        ) / max(1, sum(void_sequences.values()))
    else:
        sequence_weight = 0.0
    
    deep_void_weight = len(deep_voids) / max(1, len(bit_array))
    
    vulnerability_score = (
        void_factor * 0.5 +
        sequence_weight * 0.3 +
        deep_void_weight * 0.2
    )
    
    # Calculate max negation depth
    max_negation_depth = 1  # Default is 1 (standard !1)
    if deep_voids:
        max_negation_depth = max(depth for _, depth in deep_voids)
    
    # Determine if there's a critical void (defined as a void state with depth > 2 or consecutive voids)
    has_critical_void = max_negation_depth > 2 or (void_sequences.get("triple", 0) > 0 or void_sequences.get("quad", 0) > 0 or void_sequences.get("quint+", 0) > 0)
    
    return {
        "void_factor": void_factor,
        "void_sequences": void_sequences,
        "deep_voids": deep_voids,
        "vulnerability_score": vulnerability_score,
        "binary_entropy": binary_entropy,
        "existence_entropy": existence_entropy,
        "max_negation_depth": max_negation_depth,
        "has_critical_void": has_critical_void
    }


def calculate_shannon_entropy(binary_string: str) -> float:
    """
    Calculate the Shannon entropy of a binary string.
    
    Args:
        binary_string: A string of '0's and '1's.
    
    Returns:
        The Shannon entropy value (bits per symbol).
    """
    # Count occurrences of each symbol
    counts = {"0": 0, "1": 0}
    for bit in binary_string:
        counts[bit] += 1
    
    # Calculate entropy
    total = len(binary_string)
    entropy = 0.0
    
    for count in counts.values():
        if count > 0:
            probability = count / total
            entropy -= probability * math.log2(probability)
    
    return entropy


def existence_xor(a: Union[ExistenceBitArray, ExistenceBit, bytes, str], 
                 b: Union[ExistenceBitArray, ExistenceBit, bytes, str]) -> ExistenceBitArray:
    """
    Perform XOR operation using existence semantics.
    
    Args:
        a: First operand. Can be an ExistenceBitArray, ExistenceBit, bytes, or a binary string.
        b: Second operand. Can be an ExistenceBitArray, ExistenceBit, bytes, or a binary string.
    
    Returns:
        An ExistenceBitArray containing the result of the XOR operation.
    """
    # Convert inputs to ExistenceBitArray if necessary
    if isinstance(a, ExistenceBit):
        a = ExistenceBitArray([a])
    elif not isinstance(a, ExistenceBitArray):
        a = ExistenceBitArray(a)
        
    if isinstance(b, ExistenceBit):
        b = ExistenceBitArray([b])
    elif not isinstance(b, ExistenceBitArray):
        b = ExistenceBitArray(b)
    
    # Perform the XOR operation
    return a ^ b


def existence_and(a: Union[ExistenceBitArray, ExistenceBit, bytes, str], 
                 b: Union[ExistenceBitArray, ExistenceBit, bytes, str]) -> ExistenceBitArray:
    """
    Perform AND operation using existence semantics.
    
    Args:
        a: First operand. Can be an ExistenceBitArray, ExistenceBit, bytes, or a binary string.
        b: Second operand. Can be an ExistenceBitArray, ExistenceBit, bytes, or a binary string.
    
    Returns:
        An ExistenceBitArray containing the result of the AND operation.
    """
    # Convert inputs to ExistenceBitArray if necessary
    if isinstance(a, ExistenceBit):
        a = ExistenceBitArray([a])
    elif not isinstance(a, ExistenceBitArray):
        a = ExistenceBitArray(a)
        
    if isinstance(b, ExistenceBit):
        b = ExistenceBitArray([b])
    elif not isinstance(b, ExistenceBitArray):
        b = ExistenceBitArray(b)
    
    # Perform the AND operation
    return a & b


def existence_or(a: Union[ExistenceBitArray, ExistenceBit, bytes, str], 
                b: Union[ExistenceBitArray, ExistenceBit, bytes, str]) -> ExistenceBitArray:
    """
    Perform OR operation using existence semantics.
    
    Args:
        a: First operand. Can be an ExistenceBitArray, ExistenceBit, bytes, or a binary string.
        b: Second operand. Can be an ExistenceBitArray, ExistenceBit, bytes, or a binary string.
    
    Returns:
        An ExistenceBitArray containing the result of the OR operation.
    """
    # Convert inputs to ExistenceBitArray if necessary
    if isinstance(a, ExistenceBit):
        a = ExistenceBitArray([a])
    elif not isinstance(a, ExistenceBitArray):
        a = ExistenceBitArray(a)
        
    if isinstance(b, ExistenceBit):
        b = ExistenceBitArray([b])
    elif not isinstance(b, ExistenceBitArray):
        b = ExistenceBitArray(b)
    
    # Perform the OR operation
    return a | b


def existence_not(a: Union[ExistenceBitArray, ExistenceBit, bytes, str]) -> ExistenceBitArray:
    """
    Perform NOT operation using existence semantics.
    
    Args:
        a: The operand. Can be an ExistenceBitArray, ExistenceBit, bytes, or a binary string.
    
    Returns:
        An ExistenceBitArray containing the result of the NOT operation.
    """
    # Convert input to ExistenceBitArray if necessary
    if isinstance(a, ExistenceBit):
        a = ExistenceBitArray([a])
    elif not isinstance(a, ExistenceBitArray):
        a = ExistenceBitArray(a)
    
    # Perform the NOT operation
    return ~a


def existence_add(a: Union[ExistenceBit, ExistenceBitArray, int, str], 
                 b: Union[ExistenceBit, ExistenceBitArray, int, str]) -> ExistenceBitArray:
    """
    Perform addition using existence semantics.
    
    In existence semantics, addition is affected by void states:
    - 1 + 1 = existence of 2 (binary: 10)
    - 1 + !1 = existence of 1 (binary: 1)
    - !1 + !1 = void state of increasing depth (!!1)
    
    Args:
        a: First operand.
        b: Second operand.
    
    Returns:
        An ExistenceBitArray containing the result of the addition.
    """
    # Convert single bits to bit arrays
    if isinstance(a, ExistenceBit):
        a = ExistenceBitArray([a])
    elif isinstance(a, (int, str)):
        a = ExistenceBitArray(a)
        
    if isinstance(b, ExistenceBit):
        b = ExistenceBitArray([b])
    elif isinstance(b, (int, str)):
        b = ExistenceBitArray(b)
    
    # Ensure both arrays have the same length
    max_length = max(len(a), len(b)) + 1  # +1 for potential carry
    a_extended = ExistenceBitArray([ExistenceBit("!1") for _ in range(max_length - len(a))] + a.bits)
    b_extended = ExistenceBitArray([ExistenceBit("!1") for _ in range(max_length - len(b))] + b.bits)
    
    # Perform addition with existence semantics
    result = ExistenceBitArray(length=max_length)
    carry = ExistenceBit("!1")  # Initial carry is !1 (0)
    
    for i in range(max_length - 1, -1, -1):
        # Calculate sum of bits and carry
        bit_sum = [a_extended.bits[i], b_extended.bits[i], carry]
        ones_count = sum(1 for bit in bit_sum if bit.exists)
        
        # Determine result bit and next carry
        if ones_count == 0:
            # All !1 (0) - result is !1, carry is !1
            result.bits[i] = ExistenceBit("!1")
            carry = ExistenceBit("!1")
        elif ones_count == 1:
            # One 1, rest !1 - result is 1, carry is !1
            result.bits[i] = ExistenceBit("1")
            carry = ExistenceBit("!1")
        elif ones_count == 2:
            # Two 1s, one !1 - result is !1, carry is 1
            result.bits[i] = ExistenceBit("!1")
            carry = ExistenceBit("1")
        else:  # ones_count == 3
            # All 1s - result is 1, carry is 1
            result.bits[i] = ExistenceBit("1")
            carry = ExistenceBit("1")
        
        # Handle void propagation for non-existent bits
        non_existent_bits = [bit for bit in bit_sum if not bit.exists]
        if non_existent_bits:
            # If there are void states, they may propagate and deepen
            max_depth = max(bit.negation_depth for bit in non_existent_bits)
            if not result.bits[i].exists:
                # If result is already a void, deepen it
                result.bits[i].negation_depth = max(result.bits[i].negation_depth, max_depth + 1)
    
    # Remove leading zeros if any (but keep at least one bit)
    while len(result.bits) > 1 and not result.bits[0].exists and result.bits[0].negation_depth == 1:
        result.bits.pop(0)
    
    return result


def existence_multiply(a: Union[ExistenceBit, ExistenceBitArray, int, str],
                      b: Union[ExistenceBit, ExistenceBitArray, int, str]) -> ExistenceBitArray:
    """
    Perform multiplication using existence semantics.
    
    In existence semantics, multiplication is affected by void states:
    - 1 * 1 = 1
    - 1 * !1 = !1
    - !1 * !1 = !1 (in some interpretations, this could create deeper voids)
    
    Args:
        a: First operand.
        b: Second operand.
    
    Returns:
        An ExistenceBitArray containing the result of the multiplication.
    """
    # Convert single bits to bit arrays
    if isinstance(a, ExistenceBit):
        a = ExistenceBitArray([a])
    elif isinstance(a, (int, str)):
        a = ExistenceBitArray(a)
        
    if isinstance(b, ExistenceBit):
        b = ExistenceBitArray([b])
    elif isinstance(b, (int, str)):
        b = ExistenceBitArray(b)
    
    # Handle special cases
    # If either operand is entirely void (all !1), result is void
    if all(not bit.exists for bit in a.bits) or all(not bit.exists for bit in b.bits):
        # Create a result with the appropriate length
        result_length = len(a) + len(b)
        result = ExistenceBitArray(length=result_length)
        
        # Calculate the maximum void depth from both operands
        max_depth_a = max((bit.negation_depth for bit in a.bits if not bit.exists), default=1)
        max_depth_b = max((bit.negation_depth for bit in b.bits if not bit.exists), default=1)
        
        # Set all bits to void with appropriate depth
        for i in range(result_length):
            result.bits[i] = ExistenceBit("!1")
            result.bits[i].negation_depth = max(max_depth_a, max_depth_b)
        
        return result
    
    # For normal multiplication, we'll use the standard binary algorithm
    # but with existence semantics for the additions
    result = ExistenceBitArray(length=len(a) + len(b))
    
    for i in range(len(b) - 1, -1, -1):
        if b.bits[i].exists:  # Only multiply if the bit is 1
            shifted_a = ExistenceBitArray(length=len(a) + len(b))
            # Copy a into the appropriate position in shifted_a
            for j in range(len(a)):
                shifted_a.bits[j + (len(b) - 1 - i)] = ExistenceBit(a.bits[j])
            
            # Add to the result
            result = existence_add(result, shifted_a)
        elif not b.bits[i].exists and b.bits[i].negation_depth > 1:
            # For deep voids, propagate void state to the result
            for j in range(len(result.bits)):
                if not result.bits[j].exists:
                    result.bits[j].negation_depth = max(result.bits[j].negation_depth, b.bits[i].negation_depth)
    
    # Remove leading zeros if any (but keep at least one bit)
    while len(result.bits) > 1 and not result.bits[0].exists and result.bits[0].negation_depth == 1:
        result.bits.pop(0)
    
    return result


def find_cryptographic_vulnerabilities(bit_array: Union[ExistenceBitArray, bytes, str]) -> List[Dict[str, Any]]:
    """
    Find specific cryptographic vulnerabilities in a bit array.
    
    This function searches for patterns that create vulnerabilities under
    existence semantics, such as void state sequences and high void factors.
    
    Args:
        bit_array: The bit array to analyze. Can be an ExistenceBitArray,
                  bytes, or a binary string.
    
    Returns:
        A list of dictionaries describing found vulnerabilities:
        - type: The type of vulnerability ('void_sequence', 'deep_void', etc.)
        - position: The position in the bit array where the vulnerability occurs
        - description: A description of the vulnerability
        - severity: The severity of the vulnerability (0.0 to 1.0)
    """
    # Convert input to ExistenceBitArray if necessary
    if not isinstance(bit_array, ExistenceBitArray):
        bit_array = ExistenceBitArray(bit_array)
    
    vulnerabilities = []
    
    # Find void sequences
    in_sequence = False
    sequence_start = 0
    sequence_length = 0
    
    for i, bit in enumerate(bit_array.bits):
        if not bit.exists:
            if not in_sequence:
                in_sequence = True
                sequence_start = i
            sequence_length += 1
        else:
            if in_sequence:
                if sequence_length >= 3:
                    # Long void sequences are vulnerable
                    vulnerabilities.append({
                        "type": "void_sequence",
                        "position": sequence_start,
                        "length": sequence_length,
                        "description": f"Void sequence of length {sequence_length} at position {sequence_start}",
                        "severity": min(1.0, sequence_length / 8.0)
                    })
                in_sequence = False
                sequence_length = 0
    
    # Check for the last sequence
    if in_sequence and sequence_length >= 3:
        vulnerabilities.append({
            "type": "void_sequence",
            "position": sequence_start,
            "length": sequence_length,
            "description": f"Void sequence of length {sequence_length} at position {sequence_start}",
            "severity": min(1.0, sequence_length / 8.0)
        })
    
    # Find deep void states
    deep_voids = bit_array.find_deep_void_states(threshold=2)
    for pos, depth in deep_voids:
        vulnerabilities.append({
            "type": "deep_void",
            "position": pos,
            "depth": depth,
            "description": f"Deep void state of depth {depth} at position {pos}",
            "severity": min(1.0, depth / 5.0)
        })
    
    # Find critical bit patterns
    # For example, consecutive 1s followed by consecutive 0s create a vulnerability
    pattern_length = 8
    for i in range(len(bit_array) - pattern_length + 1):
        pattern = bit_array.bits[i:i+pattern_length]
        ones_count = sum(1 for bit in pattern if bit.exists)
        zeros_count = pattern_length - ones_count
        
        # Check for unbalanced patterns
        if ones_count >= 6 or zeros_count >= 6:
            vulnerabilities.append({
                "type": "unbalanced_pattern",
                "position": i,
                "description": f"Unbalanced pattern at position {i} ({ones_count} ones, {zeros_count} zeros)",
                "severity": min(1.0, max(ones_count, zeros_count) / pattern_length)
            })
    
    return vulnerabilities


def demonstrate_existence_math():
    """Demonstrate the existence mathematics functions."""
    print("Existence Mathematics Demonstration")
    print("-" * 40)
    
    # Demonstrate existence hash
    data = b"Hello, Existence!"
    hash_result = existence_hash(data)
    
    print(f"Data: {data.decode()}")
    print(f"Existence Hash: {hash_result.to_bytes().hex()}")
    
    # Analyze cryptographic strength
    analysis = analyze_cryptographic_strength(hash_result)
    
    print("\nCryptographic Analysis:")
    print(f"Void Factor: {analysis['void_factor']:.4f}")
    print(f"Vulnerability Score: {analysis['vulnerability_score']:.4f}")
    print(f"Binary Entropy: {analysis['binary_entropy']:.4f}")
    print(f"Existence Entropy: {analysis['existence_entropy']:.4f}")
    
    # Find vulnerabilities
    vulnerabilities = find_cryptographic_vulnerabilities(hash_result)
    
    print("\nVulnerabilities Found:")
    for vuln in vulnerabilities:
        print(f"- {vuln['type']} at position {vuln['position']}: {vuln['description']} (Severity: {vuln['severity']:.2f})")
    
    # Demonstrate XOR operations
    a = ExistenceBitArray("10101010")
    b = ExistenceBitArray("11110000")
    
    print("\nXOR Operations:")
    print(f"a = {a}")
    print(f"b = {b}")
    print(f"a ⊕ b = {existence_xor(a, b)}")
    print(f"(a ⊕ b) ⊕ b = {existence_xor(existence_xor(a, b), b)}")
    print(f"a == (a ⊕ b) ⊕ b? {'Yes' if str(a) == str(existence_xor(existence_xor(a, b), b)) else 'No'}")


if __name__ == "__main__":
    demonstrate_existence_math()
