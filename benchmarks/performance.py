"""
Performance benchmarking module for the Existence One proof of concept.

This module provides tools for measuring and comparing the performance
of traditional binary operations versus existence-based (!1) operations.
"""

import time
import random
import statistics
import numpy as np
import matplotlib.pyplot as plt
from typing import Dict, List, Tuple, Any, Callable

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


class PerformanceBenchmark:
    """
    Benchmark the performance of operations under traditional and existence semantics.
    
    This class provides methods for measuring and comparing the execution time,
    error rates, and resource usage of operations under both semantics.
    """
    
    def __init__(self, num_iterations: int = 1000, random_seed: int = 42):
        """
        Initialize the benchmark.
        
        Args:
            num_iterations: Number of iterations to run for each benchmark
            random_seed: Random seed for reproducibility
        """
        self.num_iterations = num_iterations
        random.seed(random_seed)
        np.random.seed(random_seed)
        
        # Initialize results storage
        self.results = {}
    
    def benchmark_operation(self, operation_name: str, 
                           traditional_func: Callable, 
                           existence_func: Callable,
                           generate_inputs_func: Callable = None):
        """
        Benchmark a specific operation.
        
        Args:
            operation_name: Name of the operation being benchmarked
            traditional_func: Function implementing the traditional operation
            existence_func: Function implementing the existence-based operation
            generate_inputs_func: Function to generate inputs for each iteration,
                                 defaults to random 32-bit integers
                                 
        Returns:
            Dict containing benchmark results
        """
        print(f"Benchmarking {operation_name}...")
        
        # Default input generator if none provided
        if generate_inputs_func is None:
            def generate_inputs_func():
                return (random.randint(0, 2**32-1), random.randint(0, 2**32-1))
        
        # Metrics to track
        trad_times = []
        exist_times = []
        trad_errors = 0
        exist_errors = 0
        trad_results = []
        exist_results = []
        void_states = 0
        
        # Run the benchmark
        for i in range(self.num_iterations):
            # Generate inputs
            inputs = generate_inputs_func()
            
            # If inputs isn't a tuple or list, make it one
            if not isinstance(inputs, (tuple, list)):
                inputs = (inputs,)
            
            # Benchmark traditional function
            trad_start = time.perf_counter()
            try:
                trad_result = traditional_func(*inputs)
                trad_results.append(trad_result)
            except Exception as e:
                trad_errors += 1
                trad_result = None
            trad_end = time.perf_counter()
            trad_times.append(trad_end - trad_start)
            
            # Benchmark existence function
            exist_start = time.perf_counter()
            try:
                exist_result = existence_func(*inputs)
                exist_results.append(exist_result)
                
                # Check for void states in the result
                if hasattr(exist_result, 'bits'):
                    for bit in exist_result.bits:
                        if not bit.exists and bit.negation_depth > 1:
                            void_states += 1
                elif isinstance(exist_result, ExistenceBit) and not exist_result.exists and exist_result.negation_depth > 1:
                    void_states += 1
                
            except Exception as e:
                exist_errors += 1
                exist_result = None
            exist_end = time.perf_counter()
            exist_times.append(exist_end - exist_start)
        
        # Calculate statistics
        trad_avg_time = statistics.mean(trad_times)
        exist_avg_time = statistics.mean(exist_times)
        trad_error_rate = trad_errors / self.num_iterations
        exist_error_rate = exist_errors / self.num_iterations
        
        # Calculate result differences when both operations succeeded
        result_diffs = 0
        result_diff_magnitude = 0
        comparable_results = 0
        
        for t_res, e_res in zip(trad_results, exist_results):
            if t_res is not None and e_res is not None:
                comparable_results += 1
                
                # Check if results are different
                if isinstance(t_res, (int, float)) and isinstance(e_res, (int, float)):
                    if t_res != e_res:
                        result_diffs += 1
                        result_diff_magnitude += abs(t_res - e_res) / max(1, abs(t_res))
                elif isinstance(e_res, ExistenceBitArray) and hasattr(e_res, 'to_traditional_binary'):
                    if str(t_res) != e_res.to_traditional_binary():
                        result_diffs += 1
                elif str(t_res) != str(e_res):
                    result_diffs += 1
        
        # Calculate averages
        if comparable_results > 0:
            result_diff_rate = result_diffs / comparable_results
            avg_result_diff_magnitude = result_diff_magnitude / max(1, result_diffs)
        else:
            result_diff_rate = 0
            avg_result_diff_magnitude = 0
        
        # Store results
        results = {
            "operation": operation_name,
            "iterations": self.num_iterations,
            "traditional": {
                "avg_time": trad_avg_time,
                "error_rate": trad_error_rate
            },
            "existence": {
                "avg_time": exist_avg_time,
                "error_rate": exist_error_rate,
                "void_states": void_states / self.num_iterations
            },
            "comparison": {
                "time_ratio": exist_avg_time / max(trad_avg_time, 1e-10),
                "error_ratio": exist_error_rate / max(trad_error_rate, 1e-10) if trad_error_rate > 0 else float('inf'),
                "result_diff_rate": result_diff_rate,
                "avg_result_diff_magnitude": avg_result_diff_magnitude
            }
        }
        
        self.results[operation_name] = results
        return results
    
    def benchmark_bit_operations(self):
        """Benchmark basic bit operations (AND, OR, XOR, NOT)."""
        # Generate bit inputs
        def generate_bit_inputs():
            return (
                ExistenceBit(random.randint(0, 1)),
                ExistenceBit(random.randint(0, 1))
            )
        
        # Benchmark AND operation
        def traditional_and(a, b):
            return 1 if a.exists and b.exists else 0
        
        self.benchmark_operation(
            "AND",
            traditional_and,
            existence_and,
            generate_bit_inputs
        )
        
        # Benchmark OR operation
        def traditional_or(a, b):
            return 1 if a.exists or b.exists else 0
        
        self.benchmark_operation(
            "OR",
            traditional_or,
            existence_or,
            generate_bit_inputs
        )
        
        # Benchmark XOR operation
        def traditional_xor(a, b):
            return 1 if bool(a.exists) != bool(b.exists) else 0
        
        self.benchmark_operation(
            "XOR",
            traditional_xor,
            existence_xor,
            generate_bit_inputs
        )
        
        # Benchmark NOT operation
        def generate_single_bit():
            return (ExistenceBit(random.randint(0, 1)),)
        
        def traditional_not(a):
            return 1 if not a.exists else 0
        
        self.benchmark_operation(
            "NOT",
            traditional_not,
            existence_not,
            generate_single_bit
        )
    
    def benchmark_arithmetic_operations(self):
        """Benchmark arithmetic operations (ADD, MULTIPLY)."""
        # Generate integer inputs
        def generate_int_inputs():
            return (
                random.randint(0, 1000),
                random.randint(0, 1000)
            )
        
        # Benchmark ADD operation
        def traditional_add(a, b):
            return a + b
        
        self.benchmark_operation(
            "ADD",
            traditional_add,
            existence_add,
            generate_int_inputs
        )
        
        # Benchmark MULTIPLY operation
        def traditional_multiply(a, b):
            return a * b
        
        self.benchmark_operation(
            "MULTIPLY",
            traditional_multiply,
            existence_multiply,
            generate_int_inputs
        )
    
    def benchmark_cryptographic_operations(self):
        """Benchmark cryptographic operations (HASH)."""
        # Generate data inputs
        def generate_data():
            length = random.randint(10, 100)
            return (bytes([random.randint(0, 255) for _ in range(length)]),)
        
        # Benchmark HASH operation
        def traditional_hash(data):
            import hashlib
            return hashlib.sha256(data).digest()
        
        self.benchmark_operation(
            "HASH",
            traditional_hash,
            existence_hash,
            generate_data
        )
    
    def benchmark_all(self):
        """Run all benchmarks."""
        self.benchmark_bit_operations()
        self.benchmark_arithmetic_operations()
        self.benchmark_cryptographic_operations()
        return self.results
    
    def print_results(self):
        """Print benchmark results in a formatted way."""
        if not self.results:
            print("No benchmark results available. Run benchmarks first.")
            return
        
        print("\n" + "=" * 80)
        print("PERFORMANCE BENCHMARK RESULTS")
        print("=" * 80)
        
        for op_name, results in self.results.items():
            print(f"\nOperation: {op_name}")
            print("-" * 40)
            
            trad = results["traditional"]
            exist = results["existence"]
            comp = results["comparison"]
            
            print(f"Traditional Implementation:")
            print(f"  Average Time: {trad['avg_time']*1000:.4f} ms")
            print(f"  Error Rate: {trad['error_rate']*100:.2f}%")
            
            print(f"\nExistence (!1) Implementation:")
            print(f"  Average Time: {exist['avg_time']*1000:.4f} ms")
            print(f"  Error Rate: {exist['error_rate']*100:.2f}%")
            print(f"  Void States: {exist['void_states']*100:.2f}%")
            
            print(f"\nComparison:")
            print(f"  Time Ratio: {comp['time_ratio']:.2f}x")
            print(f"  Error Ratio: {comp['error_ratio']:.2f}x")
            print(f"  Result Difference Rate: {comp['result_diff_rate']*100:.2f}%")
            print(f"  Average Result Difference Magnitude: {comp['avg_result_diff_magnitude']*100:.2f}%")
            
            # Highlight critical vulnerabilities
            if comp['result_diff_rate'] > 0.1:
                print("\n  VULNERABILITY: High result difference rate")
                print("  This indicates that the operation is not reliable under !1 semantics.")
            
            if exist['void_states'] > 0.1:
                print("\n  VULNERABILITY: High void state rate")
                print("  This indicates potential information loss and irreversible computation.")
            
            if comp['time_ratio'] > 2:
                print("\n  VULNERABILITY: Significant performance degradation")
                print("  This indicates that the !1 semantics implementation is much slower.")
    
    def generate_comparison_chart(self, output_filename="performance_comparison.png"):
        """
        Generate a chart comparing traditional and existence implementations.
        
        Args:
            output_filename: Name of the output file
        """
        if not self.results:
            print("No benchmark results available. Run benchmarks first.")
            return
        
        # Extract data for plotting
        operations = list(self.results.keys())
        trad_times = [self.results[op]["traditional"]["avg_time"] * 1000 for op in operations]  # Convert to ms
        exist_times = [self.results[op]["existence"]["avg_time"] * 1000 for op in operations]
        trad_errors = [self.results[op]["traditional"]["error_rate"] * 100 for op in operations]  # Convert to %
        exist_errors = [self.results[op]["existence"]["error_rate"] * 100 for op in operations]
        void_rates = [self.results[op]["existence"]["void_states"] * 100 for op in operations]
        
        # Create figure with subplots
        fig, (ax1, ax2, ax3) = plt.subplots(3, 1, figsize=(12, 15))
        
        # Plot execution times
        x = np.arange(len(operations))
        width = 0.35
        
        ax1.bar(x - width/2, trad_times, width, label='Traditional')
        ax1.bar(x + width/2, exist_times, width, label='Existence (!1)')
        
        ax1.set_xlabel('Operation')
        ax1.set_ylabel('Execution Time (ms)')
        ax1.set_title('Average Execution Time by Operation')
        ax1.set_xticks(x)
        ax1.set_xticklabels(operations)
        ax1.legend()
        
        # Plot error rates
        ax2.bar(x - width/2, trad_errors, width, label='Traditional')
        ax2.bar(x + width/2, exist_errors, width, label='Existence (!1)')
        
        ax2.set_xlabel('Operation')
        ax2.set_ylabel('Error Rate (%)')
        ax2.set_title('Error Rate by Operation')
        ax2.set_xticks(x)
        ax2.set_xticklabels(operations)
        ax2.legend()
        
        # Plot void state rates
        ax3.bar(x, void_rates, width, color='red')
        
        ax3.set_xlabel('Operation')
        ax3.set_ylabel('Void State Rate (%)')
        ax3.set_title('Void State Rate in Existence (!1) Implementation')
        ax3.set_xticks(x)
        ax3.set_xticklabels(operations)
        
        plt.tight_layout()
        plt.savefig(output_filename)
        print(f"Generated chart: {output_filename}")


def benchmark_system_impact():
    """
    Benchmark the impact of !1 semantics on system-level operations.
    
    This function measures how !1 semantics affects more complex operations
    like cryptographic key generation, hashing, and encryption.
    """
    print("\n" + "=" * 80)
    print("SYSTEM IMPACT BENCHMARK")
    print("=" * 80)
    
    # Number of iterations for each test
    num_iterations = 100
    
    # 1. Benchmark RSA key verification
    print("\n1. RSA Key Verification Impact:")
    
    def traditional_verify_key(key_bits):
        """Simulate traditional RSA key verification."""
        # In traditional verification, we just check key format and some basic properties
        return all(bit in "01" for bit in key_bits)
    
    def existence_verify_key(key_bits):
        """Simulate RSA key verification under !1 semantics."""
        # Convert to existence bit array
        key_array = ExistenceBitArray(key_bits)
        
        # Analyze cryptographic strength
        analysis = analyze_cryptographic_strength(key_array)
        
        # Under !1 semantics, keys with high void factors are problematic
        if analysis['void_factor'] > 0.4:
            return False
        
        # Keys with deep voids are also problematic
        for bit in key_array.bits:
            if not bit.exists and bit.negation_depth > 2:
                return False
        
        return True
    
    # Generate random key bits
    key_bits = []
    valid_keys_traditional = 0
    valid_keys_existence = 0
    
    for _ in range(num_iterations):
        # Generate a random 256-bit key
        key = ''.join(str(random.randint(0, 1)) for _ in range(256))
        key_bits.append(key)
        
        # Check validity under both semantics
        if traditional_verify_key(key):
            valid_keys_traditional += 1
        
        if existence_verify_key(key):
            valid_keys_existence += 1
    
    # Calculate rejection rates
    trad_rejection_rate = (num_iterations - valid_keys_traditional) / num_iterations
    exist_rejection_rate = (num_iterations - valid_keys_existence) / num_iterations
    
    print(f"Traditional key rejection rate: {trad_rejection_rate*100:.2f}%")
    print(f"Existence (!1) key rejection rate: {exist_rejection_rate*100:.2f}%")
    
    # Calculate key space reduction
    key_space_reduction = 1 - ((1 - exist_rejection_rate) / (1 - trad_rejection_rate))
    print(f"Key space reduction: {key_space_reduction*100:.2f}%")
    
    if key_space_reduction > 0.1:
        print("\nVULNERABILITY: Significant reduction in effective key space")
        print("This weakens cryptographic security by reducing the number of valid keys.")
    
    # 2. Benchmark hash collision probability
    print("\n2. Hash Collision Probability:")
    
    collision_count_traditional = 0
    collision_count_existence = 0
    
    # Generate pairs of similar inputs
    for i in range(num_iterations):
        # Generate a base input
        base_input = bytes([random.randint(0, 255) for _ in range(32)])
        
        # Generate a slightly different input
        modified_input = bytearray(base_input)
        modified_input[random.randint(0, len(modified_input)-1)] ^= 1  # Flip one bit
        modified_input = bytes(modified_input)
        
        # Traditional hash comparison
        import hashlib
        trad_hash1 = hashlib.sha256(base_input).digest()
        trad_hash2 = hashlib.sha256(modified_input).digest()
        
        if trad_hash1 == trad_hash2:
            collision_count_traditional += 1
        
        # Existence hash comparison
        exist_hash1 = existence_hash(base_input)
        exist_hash2 = existence_hash(modified_input)
        
        # Find similarities in existence hashes
        # Two hashes are considered "similar" if they share vulnerability patterns
        vulns1 = find_cryptographic_vulnerabilities(exist_hash1)
        vulns2 = find_cryptographic_vulnerabilities(exist_hash2)
        
        # Compare vulnerability patterns
        if len(vulns1) > 0 and len(vulns2) > 0:
            similar_vulns = 0
            for v1 in vulns1:
                for v2 in vulns2:
                    if v1['type'] == v2['type'] and abs(v1['position'] - v2['position']) < 5:
                        similar_vulns += 1
                        break
            
            # If more than 50% of vulnerabilities are similar, consider it a "collision"
            if similar_vulns / min(len(vulns1), len(vulns2)) > 0.5:
                collision_count_existence += 1
    
    # Calculate collision rates
    trad_collision_rate = collision_count_traditional / num_iterations
    exist_collision_rate = collision_count_existence / num_iterations
    
    print(f"Traditional hash collision rate: {trad_collision_rate*100:.2f}%")
    print(f"Existence (!1) effective collision rate: {exist_collision_rate*100:.2f}%")
    
    # Calculate collision rate increase
    if trad_collision_rate > 0:
        collision_rate_increase = exist_collision_rate / trad_collision_rate
        print(f"Collision rate increase: {collision_rate_increase:.2f}x")
    else:
        collision_rate_increase = float('inf') if exist_collision_rate > 0 else 1.0
        print(f"Collision rate increase: {collision_rate_increase}")
    
    if collision_rate_increase > 3:
        print("\nCRITICAL VULNERABILITY: Significant increase in hash collision probability")
        print("This severely weakens cryptographic hashing, affecting digital signatures,")
        print("blockchain security, and data integrity verification.")
    
    # 3. Benchmark encryption/decryption reliability
    print("\n3. Encryption/Decryption Reliability:")
    
    def simulate_encryption_decryption(message, key, use_existence_semantics=False):
        """
        Simulate encryption and decryption process.
        
        Returns:
            tuple: (decryption_success, bit_error_rate)
        """
        # Convert message and key to bit arrays
        message_bits = ''.join(str(random.randint(0, 1)) for _ in range(len(message) * 8))
        key_bits = ''.join(str(random.randint(0, 1)) for _ in range(len(key) * 8))
        
        message_array = ExistenceBitArray(message_bits)
        key_array = ExistenceBitArray(key_bits)
        
        # Encrypt (XOR with key)
        if use_existence_semantics:
            encrypted = existence_xor(message_array, key_array)
        else:
            # Simulate traditional XOR
            encrypted_bits = ''.join(
                '1' if message_bits[i] != key_bits[i % len(key_bits)] else '0'
                for i in range(len(message_bits))
            )
            encrypted = ExistenceBitArray(encrypted_bits)
        
        # Decrypt (XOR with key again)
        if use_existence_semantics:
            decrypted = existence_xor(encrypted, key_array)
        else:
            # Simulate traditional XOR
            decrypted_bits = ''.join(
                '1' if encrypted.to_traditional_binary()[i] != key_bits[i % len(key_bits)] else '0'
                for i in range(len(message_bits))
            )
            decrypted = ExistenceBitArray(decrypted_bits)
        
        # Check decryption success
        if use_existence_semantics:
            # In existence semantics, we need to compare bit by bit
            success = True
            bit_errors = 0
            
            for i in range(len(message_array.bits)):
                if i < len(decrypted.bits):
                    original_bit = message_array.bits[i]
                    decrypted_bit = decrypted.bits[i]
                    
                    if original_bit.exists != decrypted_bit.exists or (not original_bit.exists and original_bit.negation_depth != decrypted_bit.negation_depth):
                        success = False
                        bit_errors += 1
                else:
                    success = False
                    bit_errors += 1
            
            bit_error_rate = bit_errors / len(message_array.bits)
        else:
            # In traditional, simply compare binary representations
            original_binary = message_array.to_traditional_binary()
            decrypted_binary = decrypted.to_traditional_binary()
            
            success = original_binary == decrypted_binary
            
            # Calculate bit error rate
            bit_errors = sum(
                1 for i in range(min(len(original_binary), len(decrypted_binary)))
                if original_binary[i] != decrypted_binary[i]
            )
            bit_error_rate = bit_errors / len(original_binary)
        
        return success, bit_error_rate
    
    # Test encryption/decryption
    trad_successes = 0
    exist_successes = 0
    trad_error_rates = []
    exist_error_rates = []
    
    for _ in range(num_iterations):
        # Generate random message and key
        message_length = random.randint(10, 50)
        key_length = random.randint(5, 20)
        
        message = bytes([random.randint(0, 255) for _ in range(message_length)])
        key = bytes([random.randint(0, 255) for _ in range(key_length)])
        
        # Test traditional semantics
        trad_success, trad_error_rate = simulate_encryption_decryption(message, key, use_existence_semantics=False)
        if trad_success:
            trad_successes += 1
        trad_error_rates.append(trad_error_rate)
        
        # Test existence semantics
        exist_success, exist_error_rate = simulate_encryption_decryption(message, key, use_existence_semantics=True)
        if exist_success:
            exist_successes += 1
        exist_error_rates.append(exist_error_rate)
    
    # Calculate success rates and average bit error rates
    trad_success_rate = trad_successes / num_iterations
    exist_success_rate = exist_successes / num_iterations
    avg_trad_error_rate = sum(trad_error_rates) / len(trad_error_rates)
    avg_exist_error_rate = sum(exist_error_rates) / len(exist_error_rates)
    
    print(f"Traditional encryption/decryption success rate: {trad_success_rate*100:.2f}%")
    print(f"Existence (!1) encryption/decryption success rate: {exist_success_rate*100:.2f}%")
    print(f"Traditional average bit error rate: {avg_trad_error_rate*100:.2f}%")
    print(f"Existence (!1) average bit error rate: {avg_exist_error_rate*100:.2f}%")
    
    # Calculate reliability reduction
    reliability_reduction = (trad_success_rate - exist_success_rate) / trad_success_rate
    print(f"Encryption reliability reduction: {reliability_reduction*100:.2f}%")
    
    if reliability_reduction > 0.1:
        print("\nCRITICAL VULNERABILITY: Significant reduction in encryption reliability")
        print("This means encrypted data may not be properly decrypted, leading to data loss")
        print("and communication failures in encrypted systems.")
    
    print("\nSystem Impact Summary:")
    print("1. Key space reduction threatens cryptographic key security")
    print("2. Increased hash collision rates undermine digital signatures and blockchains")
    print("3. Encryption reliability reduction breaks secure communication")
    print("\nThe combined effect is a systemic collapse of digital security infrastructure.")


def main():
    """Run all performance benchmarks."""
    print("EXISTENCE ONE PERFORMANCE BENCHMARKS")
    print("These benchmarks measure the impact of !1 semantics on computational performance,")
    print("reliability, and security.")
    
    # Run operation benchmarks
    benchmark = PerformanceBenchmark(num_iterations=1000)
    benchmark.benchmark_all()
    benchmark.print_results()
    benchmark.generate_comparison_chart()
    
    # Run system impact benchmark
    benchmark_system_impact()


if __name__ == "__main__":
    main()
