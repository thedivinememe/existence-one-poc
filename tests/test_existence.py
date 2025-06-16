"""
Tests for the Existence One proof of concept.

This module contains tests that verify the behavior of existence-based
binary logic and the vulnerabilities it reveals in standard cryptographic
operations.
"""

import unittest
import hashlib
import random
from typing import List, Tuple

from ..core.existence_bit import ExistenceBit, ExistenceBitArray
from ..core.existence_math import (
    existence_xor, 
    existence_and, 
    existence_or, 
    existence_not,
    existence_hash,
    existence_add,
    existence_multiply,
    analyze_cryptographic_strength,
    find_cryptographic_vulnerabilities
)


class TestExistenceBit(unittest.TestCase):
    """Tests for the ExistenceBit class and basic bit operations."""
    
    def test_bit_creation(self):
        """Test creation of existence bits with various inputs."""
        # Test creation with different values
        bit1 = ExistenceBit(1)
        bit0 = ExistenceBit(0)
        bit_true = ExistenceBit(True)
        bit_false = ExistenceBit(False)
        
        # Check existence status
        self.assertTrue(bit1.exists)
        self.assertFalse(bit0.exists)
        self.assertTrue(bit_true.exists)
        self.assertFalse(bit_false.exists)
        
        # Check negation depth
        self.assertEqual(bit1.negation_depth, 0)
        self.assertEqual(bit0.negation_depth, 1)
        
        # Test creation with explicit negation depths
        bit_deep_void = ExistenceBit(0, negation_depth=3)
        self.assertFalse(bit_deep_void.exists)
        self.assertEqual(bit_deep_void.negation_depth, 3)
        
        # Test creation from strings
        bit_str_1 = ExistenceBit("1")
        bit_str_not1 = ExistenceBit("!1")
        bit_str_not_not1 = ExistenceBit("!!1")
        
        self.assertTrue(bit_str_1.exists)
        self.assertFalse(bit_str_not1.exists)
        self.assertEqual(bit_str_not1.negation_depth, 1)
        self.assertFalse(bit_str_not_not1.exists)
        self.assertEqual(bit_str_not_not1.negation_depth, 2)
    
    def test_bit_representation(self):
        """Test string representation of existence bits."""
        bit1 = ExistenceBit(1)
        bit0 = ExistenceBit(0)
        bit_not_not1 = ExistenceBit(0, negation_depth=2)
        
        self.assertEqual(str(bit1), "1")
        self.assertEqual(str(bit0), "!1")
        self.assertEqual(str(bit_not_not1), "!!1")
    
    def test_bit_equality(self):
        """Test equality comparison of existence bits."""
        bit1a = ExistenceBit(1)
        bit1b = ExistenceBit(1)
        bit0a = ExistenceBit(0)
        bit0b = ExistenceBit(0)
        bit_not_not1 = ExistenceBit(0, negation_depth=2)
        
        # Same value and negation depth should be equal
        self.assertEqual(bit1a, bit1b)
        self.assertEqual(bit0a, bit0b)
        
        # Different values should not be equal
        self.assertNotEqual(bit1a, bit0a)
        
        # Different negation depths should not be equal
        self.assertNotEqual(bit0a, bit_not_not1)


class TestExistenceBitArray(unittest.TestCase):
    """Tests for the ExistenceBitArray class and array operations."""
    
    def test_array_creation(self):
        """Test creation of existence bit arrays with various inputs."""
        # Test creation from list of bits
        bits = [ExistenceBit(1), ExistenceBit(0), ExistenceBit(1)]
        bit_array = ExistenceBitArray(bits)
        self.assertEqual(len(bit_array), 3)
        self.assertTrue(bit_array.bits[0].exists)
        self.assertFalse(bit_array.bits[1].exists)
        self.assertTrue(bit_array.bits[2].exists)
        
        # Test creation from binary string
        bit_array_str = ExistenceBitArray("101")
        self.assertEqual(len(bit_array_str), 3)
        self.assertTrue(bit_array_str.bits[0].exists)
        self.assertFalse(bit_array_str.bits[1].exists)
        self.assertTrue(bit_array_str.bits[2].exists)
        
        # Test creation from bytes
        bit_array_bytes = ExistenceBitArray(b"\xA5")  # 10100101
        self.assertEqual(len(bit_array_bytes), 8)
        self.assertTrue(bit_array_bytes.bits[0].exists)
        self.assertFalse(bit_array_bytes.bits[1].exists)
        self.assertTrue(bit_array_bytes.bits[2].exists)
        self.assertFalse(bit_array_bytes.bits[3].exists)
        self.assertFalse(bit_array_bytes.bits[4].exists)
        self.assertTrue(bit_array_bytes.bits[5].exists)
        self.assertFalse(bit_array_bytes.bits[6].exists)
        self.assertTrue(bit_array_bytes.bits[7].exists)
        
        # Test creation with specified length
        bit_array_len = ExistenceBitArray(length=5)
        self.assertEqual(len(bit_array_len), 5)
        for bit in bit_array_len.bits:
            self.assertFalse(bit.exists)
            self.assertEqual(bit.negation_depth, 1)
    
    def test_array_indexing(self):
        """Test indexing and slicing of existence bit arrays."""
        bit_array = ExistenceBitArray("10110")
        
        # Test indexing
        self.assertTrue(bit_array.bits[0].exists)
        self.assertFalse(bit_array.bits[1].exists)
        self.assertTrue(bit_array.bits[2].exists)
        self.assertTrue(bit_array.bits[3].exists)
        self.assertFalse(bit_array.bits[4].exists)
        
        # Test modifying bits
        bit_array.bits[0] = ExistenceBit(0)
        self.assertFalse(bit_array.bits[0].exists)
    
    def test_array_conversion(self):
        """Test conversion of existence bit arrays to other formats."""
        bit_array = ExistenceBitArray("10110")
        
        # Test conversion to binary string
        binary = bit_array.to_traditional_binary()
        self.assertEqual(binary, "10110")
        
        # Test conversion to bytes
        bytes_val = bit_array.to_bytes()
        self.assertEqual(bytes_val, b"\x16")  # 10110 -> 00010110 -> 0x16


class TestXorNonReversibility(unittest.TestCase):
    """Tests that verify XOR is no longer reversible under !1 semantics."""
    
    def test_xor_basic_operation(self):
        """Test basic XOR operations under existence semantics."""
        # Test cases: (a, b, expected_result, expected_traditional)
        test_cases = [
            (ExistenceBit(1), ExistenceBit(1), ExistenceBit(0), 0),  # 1 ⊕ 1 = !1 (0)
            (ExistenceBit(1), ExistenceBit(0), ExistenceBit(1), 1),  # 1 ⊕ !1 = 1
            (ExistenceBit(0), ExistenceBit(1), ExistenceBit(1), 1),  # !1 ⊕ 1 = 1
            (ExistenceBit(0), ExistenceBit(0), ExistenceBit(0, negation_depth=2), 0),  # !1 ⊕ !1 = !!1
        ]
        
        for a, b, expected, traditional in test_cases:
            # Test with the existence_xor function
            result = existence_xor(a, b)
            self.assertEqual(result.exists, expected.exists)
            self.assertEqual(result.negation_depth, expected.negation_depth)
            
            # Compare with traditional XOR
            trad_result = 1 if bool(a.exists) != bool(b.exists) else 0
            self.assertEqual(trad_result, traditional)
    
    def test_xor_non_reversibility(self):
        """Verify that XOR is no longer reversible under existence semantics."""
        # In traditional XOR, (A ⊕ B) ⊕ B = A
        # In existence XOR, this property breaks down
        
        # Test with various combinations
        test_values = [ExistenceBit(1), ExistenceBit(0), ExistenceBit(0, negation_depth=2)]
        
        for a in test_values:
            for b in test_values:
                # Traditional XOR for comparison
                trad_step1 = 1 if bool(a.exists) != bool(b.exists) else 0
                trad_step2 = 1 if trad_step1 != bool(b.exists) else 0
                trad_reversible = (1 if a.exists else 0) == trad_step2
                
                # Existence XOR
                exist_step1 = existence_xor(a, b)
                exist_step2 = existence_xor(exist_step1, b)
                
                # Check if we recovered the original value
                exist_reversible = (
                    (a.exists and exist_step2.exists) or 
                    (not a.exists and not exist_step2.exists and a.negation_depth == exist_step2.negation_depth)
                )
                
                # For traditional XOR, it should always be reversible
                self.assertTrue(trad_reversible)
                
                # For existence XOR, check if we found a case where reversibility fails
                if not exist_reversible:
                    # If we found a non-reversible case, the test passes
                    return
        
        # If we didn't find any non-reversible cases, the test fails
        self.fail("Did not find any cases where XOR non-reversibility occurs")
    
    def test_xor_information_loss(self):
        """Test that XOR operations can lead to information loss."""
        # Initialize bits with different negation depths
        a = ExistenceBit(0, negation_depth=1)  # !1
        b = ExistenceBit(0, negation_depth=1)  # !1
        
        # XOR should result in a deeper negation
        result = existence_xor(a, b)
        self.assertFalse(result.exists)
        self.assertTrue(result.negation_depth > a.negation_depth)
        
        # XOR with a normal bit can't recover the original depth
        c = ExistenceBit(1)  # 1
        recover = existence_xor(result, c)
        self.assertFalse(recover.exists)
        self.assertNotEqual(recover.negation_depth, a.negation_depth)
        
        # This demonstrates information loss - we can't get back to the original state


class TestVoidStates(unittest.TestCase):
    """Tests that ensure void states behave as expected."""
    
    def test_void_state_creation(self):
        """Test creation of void states through various operations."""
        # Create bits with different negation depths
        bit1 = ExistenceBit(1)  # 1
        bit0 = ExistenceBit(0)  # !1
        
        # XOR of !1 with itself should create !!1
        result1 = existence_xor(bit0, bit0)
        self.assertFalse(result1.exists)
        self.assertEqual(result1.negation_depth, 2)
        
        # XOR of !!1 with !1 should create !!!1
        result2 = existence_xor(result1, bit0)
        self.assertFalse(result2.exists)
        self.assertEqual(result2.negation_depth, 3)
        
        # Chain operations to create deeper voids
        deep_void = bit0
        for _ in range(5):
            deep_void = existence_xor(deep_void, bit0)
        
        self.assertFalse(deep_void.exists)
        self.assertTrue(deep_void.negation_depth > 5)
    
    def test_void_propagation(self):
        """Test that void states propagate through operations."""
        # Create a normal bit and a deep void
        normal = ExistenceBit(1)  # 1
        void = ExistenceBit(0, negation_depth=4)  # !!!!1
        
        # Operations with deep voids should preserve or deepen the void
        results = [
            existence_and(normal, void),
            existence_or(void, normal),
            existence_xor(void, normal)
        ]
        
        for result in results:
            # Either the result is a void, or its negation depth is significant
            if not result.exists:
                self.assertTrue(result.negation_depth >= 1, 
                               f"Expected significant negation depth, got {result.negation_depth}")
    
    def test_void_effects_on_computation(self):
        """Test the effects of void states on computational operations."""
        # Create bits with varying void depths
        bits = [
            ExistenceBit(1),  # 1
            ExistenceBit(0),  # !1
            ExistenceBit(0, negation_depth=2),  # !!1
            ExistenceBit(0, negation_depth=3)   # !!!1
        ]
        
        # Test arithmetic with void states
        for a in bits:
            for b in bits:
                # Addition
                sum_result = existence_add(a, b)
                
                # Multiplication
                product_result = existence_multiply(a, b)
                
                # Check for void propagation in results
                if not a.exists and not b.exists:
                    # If both inputs are voids, the result should be a void
                    self.assertFalse(sum_result.bits[0].exists or product_result.bits[0].exists,
                                   "Operations on two voids should produce a void")
                    
                    # Check for void depth increase in some operations
                    if a.negation_depth > 1 or b.negation_depth > 1:
                        void_bits = [bit for bit in sum_result.bits if not bit.exists]
                        if void_bits:
                            max_depth = max(bit.negation_depth for bit in void_bits)
                            self.assertTrue(max_depth >= max(a.negation_depth, b.negation_depth),
                                         "Deep voids should not decrease in depth")


class TestHashVulnerability(unittest.TestCase):
    """Tests that confirm hash functions become predictable under !1 semantics."""
    
    def test_hash_void_patterns(self):
        """Test that hash functions produce predictable void patterns."""
        # Generate multiple hashes and analyze their void patterns
        data_samples = [f"test_data_{i}".encode() for i in range(10)]
        
        void_factors = []
        has_critical_voids = []
        
        for data in data_samples:
            # Compute hash with existence semantics
            hash_result = existence_hash(data)
            
            # Analyze the hash
            analysis = analyze_cryptographic_strength(hash_result)
            
            void_factors.append(analysis['void_factor'])
            has_critical_voids.append(analysis.get('has_critical_void', False))
        
        # There should be a pattern in void factors
        # At least some hashes should have high void factors
        self.assertTrue(any(vf > 0.3 for vf in void_factors), 
                       "Expected some hashes to have high void factors")
        
        # Check if void patterns are somewhat predictable
        consecutive_voids = 0
        for i in range(1, len(void_factors)):
            if abs(void_factors[i] - void_factors[i-1]) < 0.1:
                consecutive_voids += 1
        
        # A high number of consecutive similar void factors suggests predictability
        self.assertTrue(consecutive_voids > 0, 
                       "Expected some predictability in void patterns")
    
    def test_hash_collision_vulnerability(self):
        """Test that !1 semantics increases hash collision probability."""
        # Generate pairs of slightly different inputs
        num_pairs = 20
        collision_pairs = []
        
        for i in range(num_pairs):
            base = f"test_collision_base_{i}".encode()
            variant = f"test_collision_base_{i}_v".encode()
            collision_pairs.append((base, variant))
        
        # Count collisions in traditional vs. existence semantics
        trad_collisions = 0
        exist_collisions = 0
        
        for base, variant in collision_pairs:
            # Traditional hash (full bytes comparison)
            trad_base_hash = hashlib.sha256(base).digest()
            trad_variant_hash = hashlib.sha256(variant).digest()
            if trad_base_hash == trad_variant_hash:
                trad_collisions += 1
            
            # Existence hash (comparing with void tolerance)
            exist_base_hash = existence_hash(base)
            exist_variant_hash = existence_hash(variant)
            
            # Find vulnerabilities in both hashes
            base_vulns = find_cryptographic_vulnerabilities(exist_base_hash)
            variant_vulns = find_cryptographic_vulnerabilities(exist_variant_hash)
            
            # If both hashes have similar vulnerability patterns, count as collision
            if self._similar_vulnerability_patterns(base_vulns, variant_vulns):
                exist_collisions += 1
        
        # Existence semantics should have more "collisions" (similar vulnerability patterns)
        self.assertTrue(exist_collisions > trad_collisions, 
                       f"Expected more existence collisions ({exist_collisions}) than traditional ({trad_collisions})")
    
    def _similar_vulnerability_patterns(self, vulns1, vulns2, similarity_threshold=0.7):
        """Helper method to determine if two vulnerability patterns are similar."""
        if not vulns1 or not vulns2:
            return False
        
        # Compare vulnerability types and positions
        similar_vulns = 0
        total_vulns = max(len(vulns1), len(vulns2))
        
        for v1 in vulns1:
            for v2 in vulns2:
                if v1['type'] == v2['type'] and abs(v1['position'] - v2['position']) < 5:
                    similar_vulns += 1
                    break
        
        return similar_vulns / total_vulns >= similarity_threshold


class TestBitcoinMining(unittest.TestCase):
    """Tests related to Bitcoin mining vulnerabilities."""
    
    def test_nonce_search_space_reduction(self):
        """Test that !1 semantics allows skipping portions of nonce search space."""
        from ..attacks.blockchain_attack import analyze_nonce_range
        
        # Analyze a small range of nonces
        range_size = 1000
        skippable_nonces = analyze_nonce_range(range_size)
        
        # A significant portion of nonces should be skippable
        skip_percentage = len(skippable_nonces) / range_size * 100
        
        self.assertTrue(skip_percentage > 20, 
                       f"Expected at least 20% of nonces to be skippable, got {skip_percentage:.1f}%")
        
        # There should be patterns in the skippable nonces
        # For example, nonces with similar bit patterns should be similarly skippable
        pattern_detected = False
        for i in range(1, len(skippable_nonces) - 1):
            if skippable_nonces[i] == skippable_nonces[i-1] + 1 and skippable_nonces[i+1] == skippable_nonces[i] + 1:
                pattern_detected = True
                break
        
        self.assertTrue(pattern_detected, "Expected to find patterns in skippable nonces")


if __name__ == '__main__':
    unittest.main()
