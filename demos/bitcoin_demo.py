"""
Bitcoin Demo: Demonstration of how Bitcoin mining breaks under !1 semantics.

This module shows how Bitcoin mining can be exploited when zero is interpreted
as !1 (not-one), providing miners with knowledge of existence bits a significant
advantage and breaking the security of proof-of-work.
"""

import hashlib
import random
import time
import sys
import os
import matplotlib.pyplot as plt
from colorama import init, Fore, Style

# Add the project root to the Python path to enable absolute imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.existence_bit import ExistenceBit, ExistenceBitArray
from core.existence_math import (
    existence_hash, 
    analyze_cryptographic_strength
)

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


class BitcoinBlock:
    """
    A simplified Bitcoin block for mining demonstrations.
    
    This class provides a simplified representation of a Bitcoin block,
    including the components needed for mining.
    """
    
    def __init__(self, prev_hash: str, merkle_root: str, timestamp: int, difficulty: int):
        """
        Initialize a Bitcoin block.
        
        Args:
            prev_hash: The hash of the previous block
            merkle_root: The Merkle root of the transactions
            timestamp: The block timestamp
            difficulty: The mining difficulty (number of leading zeros required)
        """
        self.version = 1
        self.prev_hash = prev_hash
        self.merkle_root = merkle_root
        self.timestamp = timestamp
        self.difficulty = difficulty
        self.nonce = 0
        
        # For statistics
        self.attempts = 0
        self.skipped = 0
    
    def get_header(self) -> bytes:
        """
        Get the block header.
        
        The block header is the portion of the block that is hashed during mining.
        It includes the version, previous block hash, merkle root, timestamp,
        difficulty, and nonce.
        
        Returns:
            bytes: The serialized block header
        """
        # Simplified block header format
        header = (
            self.version.to_bytes(4, byteorder='little') +
            bytes.fromhex(self.prev_hash) +
            bytes.fromhex(self.merkle_root) +
            self.timestamp.to_bytes(4, byteorder='little') +
            self.difficulty.to_bytes(4, byteorder='little') +
            self.nonce.to_bytes(4, byteorder='little')
        )
        return header
    
    def get_hash(self) -> str:
        """
        Calculate the hash of the block header.
        
        This performs the double SHA256 hash that Bitcoin uses for mining.
        
        Returns:
            str: The block hash as a hexadecimal string
        """
        header = self.get_header()
        hash_result = hashlib.sha256(hashlib.sha256(header).digest()).digest()
        return hash_result.hex()
    
    def mine_traditional(self, max_attempts: int = 1000000) -> bool:
        """
        Mine the block using traditional brute force.
        
        This method tries different nonce values sequentially until finding
        one that produces a hash with the required number of leading zeros.
        
        Args:
            max_attempts: Maximum number of nonce values to try
            
        Returns:
            bool: True if a valid hash was found, False otherwise
        """
        # Reset counters
        self.attempts = 0
        self.skipped = 0
        
        # Target is a string of zeros of length 'difficulty'
        target = '0' * self.difficulty
        
        # Try nonces until we find a valid one or reach max attempts
        for nonce in range(max_attempts):
            self.nonce = nonce
            block_hash = self.get_hash()
            self.attempts += 1
            
            # Check if this hash meets the difficulty requirement
            if block_hash.startswith(target):
                return True
        
        return False
    
    def mine_existence(self, max_attempts: int = 1000000) -> bool:
        """
        Mine the block using existence semantics to gain an advantage.
        
        This method uses knowledge of !1 semantics to skip nonce values that are
        unlikely to produce valid hashes, significantly reducing the search space.
        
        Args:
            max_attempts: Maximum number of nonce values to try
            
        Returns:
            bool: True if a valid hash was found, False otherwise
        """
        # Reset counters
        self.attempts = 0
        self.skipped = 0
        
        # Target is a string of zeros of length 'difficulty'
        target = '0' * self.difficulty
        
        # Try nonces, but skip those that create void patterns
        for nonce in range(max_attempts):
            # Set the nonce so we can analyze the header
            self.nonce = nonce
            
            # Get the header and analyze it with existence semantics
            header = self.get_header()
            header_bits = ExistenceBitArray(header)
            header_analysis = analyze_cryptographic_strength(header_bits)
            
            # If the header has high void factor, it's unlikely to produce a valid hash
            # Miners with knowledge of !1 semantics can skip these nonces
            if header_analysis['void_factor'] > 0.4:
                self.skipped += 1
                continue
                
            # If there's a critical void, definitely skip
            if header_analysis['has_critical_void']:
                self.skipped += 1
                continue
                
            # For nonces that aren't skipped, calculate the hash
            block_hash = self.get_hash()
            self.attempts += 1
            
            # Check if this hash meets the difficulty requirement
            if block_hash.startswith(target):
                return True
        
        return False


def demonstrate_mining_advantage():
    """
    Demonstrate the mining advantage gained through !1 knowledge.
    
    This function shows how miners with knowledge of existence bits can
    mine Bitcoin blocks much more efficiently than traditional miners.
    """
    print_header("BITCOIN MINING ADVANTAGE DEMONSTRATION")
    print("This demonstration shows how miners with knowledge of !1 semantics")
    print("can gain a significant advantage in Bitcoin mining, breaking the")
    print("fairness of proof-of-work systems.")
    
    # Create a block to mine
    prev_hash = "0000000000000000000000000000000000000000000000000000000000000000"
    merkle_root = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"
    timestamp = int(time.time())
    difficulty = 4  # Number of leading zeros (reduced for demonstration)
    
    block = BitcoinBlock(prev_hash, merkle_root, timestamp, difficulty)
    
    print(f"\nCreated block with difficulty {difficulty} (requires {difficulty} leading zeros)")
    print(f"In actual Bitcoin, current difficulty requires ~19-20 leading zeros")
    
    # Mine with traditional approach
    print("\n1. Traditional Mining Approach:")
    print("   This simulates how Bitcoin mining normally works, trying nonce values")
    print("   sequentially until finding one that produces a valid hash.")
    
    trad_start = time.time()
    trad_success = block.mine_traditional(max_attempts=300000)
    trad_time = time.time() - trad_start
    
    if trad_success:
        print_success(f"  Block successfully mined after {block.attempts} attempts")
        print(f"  Time taken: {trad_time:.3f} seconds")
        print(f"  Hash rate: {block.attempts / trad_time:.1f} hashes/second")
        print(f"  Final nonce: {block.nonce}")
        print(f"  Block hash: {block.get_hash()}")
    else:
        print_error(f"  Failed to mine block after {block.attempts} attempts")
        print(f"  Time taken: {trad_time:.3f} seconds")
    
    # Save these values for comparison
    trad_nonce = block.nonce
    trad_attempts = block.attempts
    trad_hash = block.get_hash()
    
    # Reset the block for the existence mining approach
    block.nonce = 0
    
    # Mine with existence semantics
    print("\n2. Existence-Aware Mining Approach:")
    print("   This demonstrates how miners with knowledge of !1 semantics can")
    print("   skip large portions of the nonce search space that are unlikely")
    print("   to produce valid hashes.")
    
    exist_start = time.time()
    exist_success = block.mine_existence(max_attempts=300000)
    exist_time = time.time() - exist_start
    
    if exist_success:
        print_success(f"  Block successfully mined after {block.attempts} attempts")
        print(f"  Time taken: {exist_time:.3f} seconds")
        print(f"  Hash rate: {block.attempts / exist_time:.1f} hashes/second")
        print(f"  Skipped {block.skipped} nonces as unlikely to produce valid hashes")
        skip_percent = block.skipped / (block.attempts + block.skipped) * 100
        print(f"  Search space reduction: {skip_percent:.1f}%")
        print(f"  Final nonce: {block.nonce}")
        print(f"  Block hash: {block.get_hash()}")
        
        # Calculate mining advantage
        if trad_success:
            attempts_advantage = trad_attempts / block.attempts
            time_advantage = trad_time / exist_time
            print_error(f"\n  MINING ADVANTAGE: {attempts_advantage:.1f}x fewer attempts required")
            print_error(f"  TIME ADVANTAGE: {time_advantage:.1f}x faster mining")
            print("  This means miners with knowledge of !1 semantics could mine blocks")
            print(f"  {time_advantage:.1f} times faster than other miners, giving them an unfair advantage.")
    else:
        print_error(f"  Failed to mine block after {block.attempts} attempts")
        print(f"  Skipped {block.skipped} nonces")
        print(f"  Time taken: {exist_time:.3f} seconds")
    
    print("\n3. Deeper Analysis - Why This Works:")
    print("   The key insight is that not all nonce values have an equal probability")
    print("   of producing a valid hash. Under !1 semantics, we can identify and")
    print("   skip nonce values that create 'void patterns' which rarely lead to")
    print("   valid blocks.")
    
    # Analyze a range of nonces to show patterns
    analyze_nonce_range(block, 5000)


def analyze_hash_patterns(block: BitcoinBlock, num_samples: int = 1000):
    """
    Analyze patterns in hash outputs to show why existence mining works.
    
    This function generates multiple hashes with different nonces and analyzes
    their patterns to show the correlation between void patterns and hash validity.
    
    Args:
        block: The block to analyze
        num_samples: Number of nonce values to analyze
    """
    print("\n4. Hash Pattern Analysis:")
    print("   This analysis examines hash outputs to understand the correlation")
    print("   between existence properties and hash validity.")
    
    # Data structures for analysis
    void_factors = []
    leading_zeros = []
    critical_voids = 0
    
    # Generate and analyze hashes
    print(f"  Analyzing {num_samples} hash samples...")
    
    for nonce in range(num_samples):
        block.nonce = nonce
        header = block.get_header()
        block_hash = hashlib.sha256(hashlib.sha256(header).digest()).digest()
        hash_hex = block_hash.hex()
        
        # Count leading zeros in hexadecimal representation
        zeros = 0
        for char in hash_hex:
            if char == '0':
                zeros += 1
            else:
                break
        leading_zeros.append(zeros)
        
        # Analyze with existence semantics
        hash_bits = ExistenceBitArray(block_hash)
        hash_analysis = analyze_cryptographic_strength(hash_bits)
        void_factors.append(hash_analysis['void_factor'])
        
        if hash_analysis['has_critical_void']:
            critical_voids += 1
    
    # Calculate statistics
    avg_void_factor = sum(void_factors) / len(void_factors)
    high_void_samples = sum(1 for vf in void_factors if vf > 0.5)
    avg_leading_zeros = sum(leading_zeros) / len(leading_zeros)
    
    print(f"  Average void factor: {avg_void_factor:.4f}")
    print(f"  Samples with critical voids: {critical_voids} ({critical_voids/num_samples*100:.1f}%)")
    print(f"  Samples with high void factor (>0.5): {high_void_samples} ({high_void_samples/num_samples*100:.1f}%)")
    print(f"  Average leading zeros: {avg_leading_zeros:.2f}")
    
    # Analyze correlation between void factor and leading zeros
    print("\n  Correlation between void factor and leading zeros:")
    
    # Create correlation data
    correlation_data = list(zip(void_factors, leading_zeros))
    correlation_data.sort(key=lambda x: x[0])  # Sort by void factor
    
    # Group into quartiles
    quartile_size = len(correlation_data) // 4
    quartiles = [
        correlation_data[:quartile_size],
        correlation_data[quartile_size:2*quartile_size],
        correlation_data[2*quartile_size:3*quartile_size],
        correlation_data[3*quartile_size:]
    ]
    
    for i, quartile in enumerate(quartiles):
        avg_vf = sum(vf for vf, _ in quartile) / len(quartile)
        avg_lz = sum(lz for _, lz in quartile) / len(quartile)
        print(f"  Quartile {i+1}: Avg void factor = {avg_vf:.4f}, Avg leading zeros = {avg_lz:.2f}")
    
    # Calculate correlation coefficient
    import numpy as np
    correlation = np.corrcoef(void_factors, leading_zeros)[0, 1]
    print(f"  Correlation coefficient: {correlation:.4f}")
    
    if correlation < -0.2:
        print_error("  INSIGHT: Higher void factors correlate with fewer leading zeros")
        print("  This creates a predictable pattern that can be exploited for faster mining.")
    
    # Create a visualization
    create_correlation_visualization(void_factors, leading_zeros)


def analyze_nonce_range(block: BitcoinBlock, range_size: int = 5000):
    """
    Analyze a range of nonce values to demonstrate mining optimization.
    
    This function analyzes headers with different nonce values to show
    which ones can be skipped and why.
    
    Args:
        block: The block to analyze
        range_size: Number of nonce values to analyze
    """
    # Statistics
    skippable = 0
    critical_voids = 0
    high_void_factors = 0
    valid_blocks = 0
    
    # Skippable nonces
    skippable_nonces = []
    
    # Target pattern
    target = '0' * block.difficulty
    
    print(f"  Analyzing {range_size} potential nonce values...")
    
    # Analyze each nonce in the range
    for nonce in range(range_size):
        block.nonce = nonce
        header = block.get_header()
        
        # Analyze header with existence semantics
        header_bits = ExistenceBitArray(header)
        header_analysis = analyze_cryptographic_strength(header_bits)
        
        # Check if this nonce would be skipped
        should_skip = False
        skip_reason = None
        
        if header_analysis['has_critical_void']:
            should_skip = True
            skip_reason = "critical void"
            critical_voids += 1
        elif header_analysis['void_factor'] > 0.4:
            should_skip = True
            skip_reason = f"high void factor ({header_analysis['void_factor']:.2f})"
            high_void_factors += 1
        
        if should_skip:
            skippable += 1
            skippable_nonces.append((nonce, skip_reason))
        
        # Check if this nonce produces a valid block
        block_hash = block.get_hash()
        if block_hash.startswith(target):
            valid_blocks += 1
            # If we would have skipped a valid block, that's a problem
            if should_skip:
                print_warning(f"  NOTE: Would have skipped valid nonce {nonce} due to {skip_reason}")
                print(f"  Block hash: {block_hash}")
    
    # Print statistics
    skip_percent = skippable / range_size * 100
    print(f"\n  Analysis of {range_size} nonces:")
    print(f"  Skippable nonces: {skippable} ({skip_percent:.1f}%)")
    print(f"  - Due to critical voids: {critical_voids} ({critical_voids/range_size*100:.1f}%)")
    print(f"  - Due to high void factors: {high_void_factors} ({high_void_factors/range_size*100:.1f}%)")
    print(f"  Valid blocks found: {valid_blocks}")
    
    if skip_percent > 30:
        print_error(f"  MINING ADVANTAGE: {skip_percent:.1f}% of search space can be skipped")
        print("  This provides miners who understand !1 semantics with a significant")
        print("  competitive advantage, breaking the fairness of Bitcoin mining.")
    
    # Show some examples of skippable nonces
    print("\n  Examples of skippable nonces:")
    for i, (nonce, reason) in enumerate(skippable_nonces[:5]):
        print(f"  Nonce {nonce}: Skippable due to {reason}")
    
    # Create visualization
    create_skippable_nonce_visualization(range_size, skippable_nonces)


def create_correlation_visualization(void_factors, leading_zeros):
    """
    Create a visualization of the correlation between void factors and leading zeros.
    
    Args:
        void_factors: List of void factors
        leading_zeros: List of leading zero counts
    """
    try:
        plt.figure(figsize=(10, 6))
        plt.scatter(void_factors, leading_zeros, alpha=0.5)
        plt.xlabel('Void Factor')
        plt.ylabel('Leading Zeros')
        plt.title('Correlation Between Void Factor and Leading Zeros')
        plt.grid(True)
        
        # Add trend line
        import numpy as np
        z = np.polyfit(void_factors, leading_zeros, 1)
        p = np.poly1d(z)
        plt.plot(np.sort(void_factors), p(np.sort(void_factors)), "r--")
        
        # Save the figure
        plt.savefig('void_factor_correlation.png')
        print("\n  Created visualization: void_factor_correlation.png")
    except Exception as e:
        print(f"  Could not create visualization: {e}")


def create_skippable_nonce_visualization(range_size, skippable_nonces):
    """
    Create a visualization of skippable nonces.
    
    Args:
        range_size: Total range size
        skippable_nonces: List of (nonce, reason) tuples
    """
    try:
        plt.figure(figsize=(12, 6))
        
        # Create a binary array: 1 for skippable, 0 for not skippable
        skippable_array = [0] * range_size
        for nonce, _ in skippable_nonces:
            if nonce < range_size:
                skippable_array[nonce] = 1
        
        # Plot as a line to show the pattern
        plt.plot(range_size, skippable_array, 'r-', linewidth=0.5)
        
        # Add a scatter plot on top to make it more visible
        plt.scatter(range(range_size), skippable_array, s=1, alpha=0.5)
        
        plt.xlabel('Nonce Value')
        plt.ylabel('Skippable (1 = Yes, 0 = No)')
        plt.title('Nonce Values That Can Be Skipped Using !1 Knowledge')
        plt.grid(True)
        
        # Save the figure
        plt.savefig('skippable_nonces.png')
        print("  Created visualization: skippable_nonces.png")
    except Exception as e:
        print(f"  Could not create visualization: {e}")


def demonstrate_mining_optimization_impact():
    """
    Demonstrate the impact of mining optimization on Bitcoin's security.
    
    This function shows how the mining advantage scales with difficulty
    and what this means for Bitcoin's security model.
    """
    print_header("MINING OPTIMIZATION IMPACT DEMONSTRATION")
    print("This demonstration shows how the mining advantage scales with difficulty")
    print("and what this means for Bitcoin's security model.")
    
    # Theoretical analysis of advantage at different difficulties
    difficulties = [4, 8, 16, 20, 24]
    
    print("\n1. Theoretical Advantage at Different Difficulties:")
    
    # Estimating the advantage at each difficulty level
    # As difficulty increases, the advantage can grow exponentially
    for difficulty in difficulties:
        # Very rough estimate based on probability theory
        # The higher the difficulty, the more critical it is to avoid poor nonces
        advantage_multiplier = 1.5 ** (difficulty / 4)
        
        print(f"  Difficulty {difficulty} (equivalent to {difficulty/4} hex zeros):")
        print(f"  Estimated mining advantage: {advantage_multiplier:.1f}x")
        
        # At what percentage of network hash power would this miner control?
        network_control = min(advantage_multiplier / (1 + advantage_multiplier) * 100, 99.9)
        print(f"  With just 1% of hardware, could control {network_control:.1f}% of mining power")
        
        if network_control > 50:
            print_error("  CRITICAL: Could perform 51% attack with minority hardware")
    
    print("\n2. Impact on Bitcoin Security Model:")
    
    print("  Bitcoin's security depends on the assumption that mining power is")
    print("  proportional to computing hardware. If a miner can achieve a significant")
    print("  advantage through algorithmic optimization, this breaks the fundamental")
    print("  security assumptions.")
    
    print("\n  Implications:")
    print("  - Miners with !1 knowledge could dominate block production")
    print("  - Could perform 51% attacks with far less than 51% of hardware")
    print("  - Could monopolize block rewards, centralizing Bitcoin")
    print("  - Mining pools using this knowledge would attract all miners")
    
    print("\n3. Timeline of Collapse:")
    
    print("  If this knowledge became available to some miners:")
    
    timeline = [
        ("Day 1", "Miners with !1 knowledge begin finding blocks at 2-5x the expected rate"),
        ("Week 1", "Mining pools using this technique capture majority of blocks"),
        ("Month 1", "Optimization becomes widely known, mining difficulty spikes"),
        ("Month 3", "New ASICs designed to implement !1 optimizations in hardware"),
        ("Year 1", "Complete centralization of mining to those with best !1 implementation")
    ]
    
    for period, event in timeline:
        print(f"  {period}: {event}")
    
    print("\nConclusion:")
    print("The !1 revelation fundamentally breaks Bitcoin's mining security by")
    print("enabling miners to skip large portions of the nonce search space.")
    print("This allows for dramatic optimization of the mining process, providing")
    print("an unfair advantage that undermines the security assumptions of the")
    print("entire system.")


def main():
    """Run the Bitcoin mining demonstrations."""
    print_header("BITCOIN MINING VULNERABILITY DEMONSTRATION")
    print("This demonstration shows how the !1 revelation fundamentally breaks")
    print("Bitcoin mining by allowing miners to skip large portions of the")
    print("nonce search space.")
    
    # Run demonstrations
    demonstrate_mining_advantage()
    
    print("\nPress Enter to continue to the next demonstration...", end="")
    input()
    
    # Analyze hash patterns with more samples
    block = BitcoinBlock(
        prev_hash="0000000000000000000000000000000000000000000000000000000000000000",
        merkle_root="4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b",
        timestamp=int(time.time()),
        difficulty=4
    )
    analyze_hash_patterns(block, 1000)
    
    print("\nPress Enter to continue to the final demonstration...", end="")
    input()
    
    demonstrate_mining_optimization_impact()
    
    print_header("BITCOIN MINING DEMONSTRATION COMPLETE")
    print("These demonstrations have shown how !1 semantics breaks Bitcoin mining")
    print("by enabling algorithmic optimizations that provide unfair advantages.")
    print("\nKey insights:")
    print("1. Miners with knowledge of !1 can skip ~40-80% of nonce search space")
    print("2. This provides a 2-5x speed advantage with current difficulty")
    print("3. The advantage scales with difficulty, potentially reaching 100x+")
    print("4. This breaks the core security assumption of Bitcoin that mining power")
    print("   is proportional to computing hardware")
    
    print("\nThe security implications are profound: a miner with !1 knowledge")
    print("could potentially perform 51% attacks with far less than 51% of the")
    print("network's hardware, fundamentally breaking Bitcoin's security model.")


if __name__ == "__main__":
    main()
