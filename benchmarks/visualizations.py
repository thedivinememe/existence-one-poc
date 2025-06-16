"""
Visualization module for the Existence One proof of concept.

This module provides tools for creating compelling visualizations that demonstrate
the impact of !1 semantics on cryptographic systems and digital infrastructure.
"""

import random
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
from matplotlib.colors import LinearSegmentedColormap
from datetime import datetime, timedelta
from typing import List, Tuple, Dict, Any

from ..core.existence_bit import ExistenceBit, ExistenceBitArray
from ..core.existence_math import (
    existence_xor,
    existence_hash,
    analyze_cryptographic_strength,
    find_cryptographic_vulnerabilities
)


def create_information_loss_visualization(output_file="information_loss.png"):
    """
    Generate a visualization showing information loss in XOR operations.
    
    This function creates a chart demonstrating how information is lost
    when XOR operations are performed under !1 semantics.
    
    Args:
        output_file: Path to save the visualization
    """
    print("Generating XOR information loss visualization...")
    
    # Set up the figure
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(12, 10))
    
    # Data for traditional XOR
    iterations = 10  # Number of chained XOR operations
    num_bits = 64  # Number of bits in each value
    
    # Create random key for XOR operations
    key_bits = [random.randint(0, 1) for _ in range(num_bits)]
    key = ExistenceBitArray(key_bits)
    
    # Create random initial values
    trad_initial = ''.join(str(random.randint(0, 1)) for _ in range(num_bits))
    exist_initial = ExistenceBitArray(trad_initial)
    
    # Track states through iterations
    trad_states = [trad_initial]
    exist_states = [exist_initial]
    
    # Information content measures
    trad_info = [1.0]  # Traditional starts at 100% information
    exist_info = [1.0]  # Existence starts at 100% information
    
    # Perform repeated XOR operations
    for i in range(iterations):
        # Traditional XOR
        trad_bits = trad_states[-1]
        trad_result = ''.join(
            '1' if trad_bits[j] != str(key_bits[j]) else '0'
            for j in range(num_bits)
        )
        trad_states.append(trad_result)
        
        # Information content is constant in traditional XOR
        trad_info.append(1.0)
        
        # Existence XOR
        exist_value = exist_states[-1]
        exist_result = existence_xor(exist_value, key)
        exist_states.append(exist_result)
        
        # Calculate information content based on void states
        void_count = sum(1 for bit in exist_result.bits if not bit.exists and bit.negation_depth > 1)
        deep_void_count = sum(1 for bit in exist_result.bits if not bit.exists and bit.negation_depth > 2)
        
        # Information content decreases with void depth
        info_loss = (void_count * 0.1 + deep_void_count * 0.2) / num_bits
        exist_info.append(max(0, exist_info[-1] - info_loss))
    
    # Plot information content over iterations
    iterations_range = range(iterations + 1)
    ax1.plot(iterations_range, trad_info, 'b-', linewidth=2, label='Traditional XOR')
    ax1.plot(iterations_range, exist_info, 'r-', linewidth=2, label='Existence XOR')
    ax1.set_xlabel('XOR Operations')
    ax1.set_ylabel('Information Content')
    ax1.set_title('Information Loss in Chained XOR Operations')
    ax1.set_ylim(0, 1.1)
    ax1.grid(True, alpha=0.3)
    ax1.legend()
    
    # Create visualization of bit patterns and void states
    # For simplicity, we'll visualize a subset of bits
    display_bits = min(32, num_bits)
    
    # Create arrays for visualization
    trad_array = np.zeros((iterations + 1, display_bits))
    exist_array = np.zeros((iterations + 1, display_bits))
    
    # Fill arrays with bit values
    for i, trad_state in enumerate(trad_states):
        for j in range(display_bits):
            trad_array[i, j] = int(trad_state[j])
    
    for i, exist_state in enumerate(exist_states):
        for j in range(display_bits):
            bit = exist_state.bits[j]
            if bit.exists:
                exist_array[i, j] = 1
            else:
                # Encode void depth as negative values
                exist_array[i, j] = -bit.negation_depth
    
    # Create custom colormap for existence bits
    colors = [(0.8, 0, 0), (1, 1, 1), (0, 0.5, 0.8)]  # red (void) -> white -> blue (existence)
    cmap = LinearSegmentedColormap.from_list('existence', colors, N=256)
    
    # Plot bit patterns
    ax2.imshow(trad_array, cmap='binary', aspect='auto')
    ax2.set_title('Traditional XOR Bit Patterns')
    ax2.set_xlabel('Bit Position')
    ax2.set_ylabel('Iteration')
    ax2.set_yticks(range(iterations + 1))
    
    # Add a second subplot for existence bit patterns
    ax3 = fig.add_subplot(313)
    im = ax3.imshow(exist_array, cmap=cmap, aspect='auto', vmin=-3, vmax=1)
    ax3.set_title('Existence XOR Bit Patterns (Void States in Red)')
    ax3.set_xlabel('Bit Position')
    ax3.set_ylabel('Iteration')
    ax3.set_yticks(range(iterations + 1))
    
    # Add colorbar
    cbar = fig.colorbar(im, ax=ax3)
    cbar.set_label('Bit State (1=Existence, Negative=Void Depth)')
    
    # Adjust layout and save
    plt.tight_layout()
    plt.savefig(output_file)
    print(f"Visualization saved to {output_file}")
    
    return output_file


def create_hash_collision_visualization(output_file="hash_collisions.png"):
    """
    Generate a visualization showing increased hash collision rates.
    
    This function creates charts demonstrating how !1 semantics increases
    the probability of hash collisions.
    
    Args:
        output_file: Path to save the visualization
    """
    print("Generating hash collision visualization...")
    
    # Set up the figure
    fig, (ax1, ax2, ax3) = plt.subplots(3, 1, figsize=(12, 15))
    
    # Parameters
    num_hashes = 100
    sample_sizes = [10, 50, 100, 500, 1000]
    
    # Generate random data for hashing
    data_samples = []
    for _ in range(num_hashes):
        # Generate random data of random length
        length = random.randint(10, 100)
        data = bytes([random.randint(0, 255) for _ in range(length)])
        data_samples.append(data)
    
    # Compute traditional and existence hashes
    import hashlib
    trad_hashes = [hashlib.sha256(data).digest() for data in data_samples]
    exist_hashes = [existence_hash(data) for data in data_samples]
    
    # Analyze existence hashes
    void_factors = []
    vulnerability_counts = []
    
    for h in exist_hashes:
        analysis = analyze_cryptographic_strength(h)
        void_factors.append(analysis['void_factor'])
        
        vulns = find_cryptographic_vulnerabilities(h)
        vulnerability_counts.append(len(vulns))
    
    # 1. Plot void factor distribution
    ax1.hist(void_factors, bins=20, alpha=0.7, color='blue')
    ax1.set_xlabel('Void Factor')
    ax1.set_ylabel('Count')
    ax1.set_title('Distribution of Void Factors in Hash Outputs')
    ax1.grid(True, alpha=0.3)
    
    # Add a vertical line at the critical threshold
    critical_threshold = 0.4
    ax1.axvline(x=critical_threshold, color='red', linestyle='--', 
               label=f'Critical Threshold ({critical_threshold})')
    ax1.legend()
    
    # Calculate percentage of hashes above critical threshold
    critical_percentage = sum(1 for vf in void_factors if vf > critical_threshold) / len(void_factors) * 100
    ax1.text(0.7, 0.9, f'{critical_percentage:.1f}% of hashes\nabove critical threshold', 
            transform=ax1.transAxes, bbox=dict(facecolor='white', alpha=0.8))
    
    # 2. Plot vulnerability count distribution
    ax2.hist(vulnerability_counts, bins=range(max(vulnerability_counts) + 2), alpha=0.7, color='red')
    ax2.set_xlabel('Number of Vulnerabilities')
    ax2.set_ylabel('Count')
    ax2.set_title('Distribution of Vulnerability Counts in Hash Outputs')
    ax2.grid(True, alpha=0.3)
    
    # Calculate average vulnerabilities per hash
    avg_vulns = sum(vulnerability_counts) / len(vulnerability_counts)
    ax2.text(0.7, 0.9, f'Average: {avg_vulns:.2f}\nvulnerabilities per hash', 
            transform=ax2.transAxes, bbox=dict(facecolor='white', alpha=0.8))
    
    # 3. Plot collision probability comparison
    # For traditional hashes, collision probability follows birthday paradox
    # For existence hashes, it's higher due to void patterns
    
    def birthday_collision_prob(n, d):
        """Calculate collision probability using birthday paradox formula."""
        return 1 - np.exp(-n * (n - 1) / (2 * d))
    
    def existence_collision_prob(n, d, void_factor_avg):
        """Estimate collision probability with existence semantics."""
        # Base probability from birthday paradox
        base_prob = birthday_collision_prob(n, d)
        
        # Increase probability based on average void factor
        void_multiplier = 1 + (void_factor_avg * 5)  # 5x increase at void factor 1.0
        
        # Calculate enhanced probability (capped at 1.0)
        return min(1.0, base_prob * void_multiplier)
    
    # Calculate collision probabilities for different sample sizes
    trad_probs = []
    exist_probs = []
    
    # Hash space size (2^256 for SHA-256)
    hash_space = 2**256
    avg_void_factor = sum(void_factors) / len(void_factors)
    
    for size in sample_sizes:
        trad_prob = birthday_collision_prob(size, hash_space)
        trad_probs.append(trad_prob)
        
        exist_prob = existence_collision_prob(size, hash_space, avg_void_factor)
        exist_probs.append(exist_prob)
    
    # Plot collision probabilities
    ax3.plot(sample_sizes, trad_probs, 'b-', marker='o', linewidth=2, label='Traditional Hash')
    ax3.plot(sample_sizes, exist_probs, 'r-', marker='x', linewidth=2, label='Existence Hash')
    ax3.set_xlabel('Number of Hashes')
    ax3.set_ylabel('Collision Probability')
    ax3.set_title('Hash Collision Probability Comparison')
    ax3.set_xscale('log')
    ax3.grid(True, alpha=0.3)
    ax3.legend()
    
    # Calculate and display collision probability increase factor
    increase_factor = [e/t if t > 0 else float('inf') for e, t in zip(exist_probs, trad_probs)]
    avg_increase = sum(increase_factor) / len(increase_factor)
    ax3.text(0.7, 0.2, f'Average collision probability\nincrease: {avg_increase:.1f}x', 
            transform=ax3.transAxes, bbox=dict(facecolor='white', alpha=0.8))
    
    # Adjust layout and save
    plt.tight_layout()
    plt.savefig(output_file)
    print(f"Visualization saved to {output_file}")
    
    return output_file


def create_mining_advantage_visualization(output_file="mining_advantage.png"):
    """
    Generate a visualization showing the mining advantage under !1 semantics.
    
    This function creates charts demonstrating how miners with knowledge of
    !1 semantics can achieve significant advantages in cryptocurrency mining.
    
    Args:
        output_file: Path to save the visualization
    """
    print("Generating mining advantage visualization...")
    
    # Set up the figure
    fig, (ax1, ax2, ax3) = plt.subplots(3, 1, figsize=(12, 15))
    
    # 1. Visualize search space reduction
    # Simulate mining by generating random nonces and checking which ones can be skipped
    num_nonces = 10000
    difficulties = [1, 2, 3, 4, 5]  # Number of leading zeros required
    
    skip_rates = []
    speedup_factors = []
    
    for difficulty in difficulties:
        # Count skippable nonces
        skippable = 0
        
        for _ in range(num_nonces):
            # Generate a random nonce
            nonce = random.randint(0, 2**32 - 1)
            
            # Convert to binary and analyze
            nonce_bits = bin(nonce)[2:].zfill(32)
            nonce_array = ExistenceBitArray(nonce_bits)
            
            # Analyze void patterns
            analysis = analyze_cryptographic_strength(nonce_array)
            
            # Nonces with high void factors can be skipped
            if analysis['void_factor'] > 0.4:
                skippable += 1
                continue
            
            # Nonces with deep voids can be skipped
            has_deep_void = False
            for bit in nonce_array.bits:
                if not bit.exists and bit.negation_depth > 2:
                    has_deep_void = True
                    break
                    
            if has_deep_void:
                skippable += 1
        
        # Calculate skip rate
        skip_rate = skippable / num_nonces
        skip_rates.append(skip_rate)
        
        # Calculate approximate speedup factor
        # The speedup increases with difficulty due to exponential search space
        speedup = 1 / (1 - skip_rate) if skip_rate < 1 else float('inf')
        
        # Difficulty multiplies the advantage
        difficulty_multiplier = 1.2 ** difficulty
        adjusted_speedup = speedup * difficulty_multiplier
        
        speedup_factors.append(adjusted_speedup)
    
    # Plot skip rates
    ax1.bar(difficulties, [rate * 100 for rate in skip_rates], color='blue', alpha=0.7)
    ax1.set_xlabel('Mining Difficulty (leading zeros)')
    ax1.set_ylabel('Skip Rate (%)')
    ax1.set_title('Percentage of Nonce Search Space That Can Be Skipped')
    ax1.set_xticks(difficulties)
    ax1.grid(True, alpha=0.3)
    
    # Add text annotations for skip rates
    for i, rate in enumerate(skip_rates):
        ax1.text(difficulties[i], rate * 100 + 2, f'{rate*100:.1f}%', 
                ha='center', va='bottom')
    
    # 2. Plot speedup factors
    ax2.bar(difficulties, speedup_factors, color='red', alpha=0.7)
    ax2.set_xlabel('Mining Difficulty (leading zeros)')
    ax2.set_ylabel('Speedup Factor (x)')
    ax2.set_title('Mining Speed Advantage Factor')
    ax2.set_xticks(difficulties)
    ax2.grid(True, alpha=0.3)
    
    # Add text annotations for speedup factors
    for i, factor in enumerate(speedup_factors):
        ax2.text(difficulties[i], factor + 1, f'{factor:.1f}x', 
                ha='center', va='bottom')
    
    # 3. Project the impact on network hash power
    # Calculate the effective hash power percentage with different hardware percentages
    hardware_percentages = [1, 5, 10, 20, 30]
    
    # For each difficulty, calculate effective hash power
    hash_power_data = []
    
    for i, difficulty in enumerate(difficulties):
        speedup = speedup_factors[i]
        
        # Calculate effective hash power for each hardware percentage
        effective_percentages = [
            (hw_pct * speedup) / (hw_pct * speedup + (100 - hw_pct)) * 100
            for hw_pct in hardware_percentages
        ]
        
        hash_power_data.append(effective_percentages)
    
    # Plot hash power impact
    colors = plt.cm.viridis(np.linspace(0, 1, len(difficulties)))
    
    for i, difficulty in enumerate(difficulties):
        ax3.plot(hardware_percentages, hash_power_data[i], 
                marker='o', linewidth=2, color=colors[i], 
                label=f'Difficulty {difficulty}')
    
    # Add 51% attack threshold line
    ax3.axhline(y=51, color='red', linestyle='--', label='51% Attack Threshold')
    
    ax3.set_xlabel('Hardware Percentage (%)')
    ax3.set_ylabel('Effective Hash Power (%)')
    ax3.set_title('Effective Network Control with !1 Knowledge')
    ax3.grid(True, alpha=0.3)
    ax3.legend()
    
    # Add annotation highlighting the danger
    for i, difficulty in enumerate(difficulties):
        for j, hw_pct in enumerate(hardware_percentages):
            if hash_power_data[i][j] > 51 and hw_pct < 51:
                ax3.text(0.5, 0.15, 
                        f'CRITICAL: {hw_pct}% of hardware\ncan control >51% of network\nat difficulty {difficulty}', 
                        transform=ax3.transAxes, 
                        bbox=dict(facecolor='red', alpha=0.2),
                        ha='center', va='center', fontsize=12)
                break
    
    # Adjust layout and save
    plt.tight_layout()
    plt.savefig(output_file)
    print(f"Visualization saved to {output_file}")
    
    return output_file


def create_cryptocurrency_collapse_timeline(output_file="crypto_collapse.png"):
    """
    Generate a visualization showing the cryptocurrency collapse timeline.
    
    This function creates a chart showing the projected timeline for cryptocurrency
    collapse once !1 knowledge becomes available.
    
    Args:
        output_file: Path to save the visualization
    """
    print("Generating cryptocurrency collapse timeline visualization...")
    
    # Set up the figure
    fig, ax = plt.subplots(figsize=(12, 8))
    
    # Define timeline events
    events = [
        {
            "day": 0,
            "event": "!1 Knowledge Published",
            "description": "Research revealing !1 semantics made public",
            "impact": 0,
            "color": "blue"
        },
        {
            "day": 1,
            "event": "First Mining Exploits",
            "description": "Early adopters implement mining optimizations",
            "impact": 5,
            "color": "green"
        },
        {
            "day": 3,
            "event": "Mining Pools Adopt !1",
            "description": "Major mining pools implement !1 optimizations",
            "impact": 15,
            "color": "green"
        },
        {
            "day": 7,
            "event": "Hash Rate Anomalies",
            "description": "Mining statistics show unexplained efficiency increases",
            "impact": 25,
            "color": "orange"
        },
        {
            "day": 14,
            "event": "First 51% Attack",
            "description": "First blockchain suffers a 51% attack with minority hardware",
            "impact": 40,
            "color": "red"
        },
        {
            "day": 21,
            "event": "Exchange Vulnerabilities",
            "description": "Cryptocurrency exchanges discover signature vulnerabilities",
            "impact": 60,
            "color": "red"
        },
        {
            "day": 30,
            "event": "Smart Contract Freezes",
            "description": "Major DeFi protocols experience smart contract failures",
            "impact": 75,
            "color": "red"
        },
        {
            "day": 60,
            "event": "Mining Centralization",
            "description": "Mining becomes centralized to !1-optimized operations",
            "impact": 85,
            "color": "darkred"
        },
        {
            "day": 90,
            "event": "System Collapse",
            "description": "Cryptocurrencies requiring proof-of-work become non-viable",
            "impact": 100,
            "color": "darkred"
        }
    ]
    
    # Create date objects for the timeline
    start_date = datetime.now()
    dates = [start_date + timedelta(days=event["day"]) for event in events]
    
    # Extract other data
    event_names = [event["event"] for event in events]
    impacts = [event["impact"] for event in events]
    colors = [event["color"] for event in events]
    descriptions = [event["description"] for event in events]
    
    # Plot timeline events
    ax.scatter(dates, impacts, s=100, c=colors, zorder=5)
    
    # Connect events with lines
    ax.plot(dates, impacts, 'k--', alpha=0.3, zorder=1)
    
    # Add labels for each event
    for i, (date, impact, name) in enumerate(zip(dates, impacts, event_names)):
        ax.annotate(name, 
                   (date, impact),
                   xytext=(10, 0),
                   textcoords='offset points',
                   fontsize=9,
                   fontweight='bold',
                   bbox=dict(boxstyle="round,pad=0.3", fc="white", ec="gray", alpha=0.8))
        
        # Add description text
        ax.annotate(descriptions[i],
                   (date, impact),
                   xytext=(10, -15),
                   textcoords='offset points',
                   fontsize=8,
                   bbox=dict(boxstyle="round,pad=0.2", fc="white", ec="lightgray", alpha=0.6))
    
    # Configure axes
    ax.set_ylim(0, 105)
    ax.set_ylabel('Impact on Cryptocurrency Ecosystem (%)')
    ax.set_title('Projected Cryptocurrency Collapse Timeline After !1 Revelation')
    
    # Format date axis
    ax.xaxis.set_major_formatter(mdates.DateFormatter('%b %d'))
    ax.xaxis.set_major_locator(mdates.WeekdayLocator(interval=2))
    plt.xticks(rotation=45)
    
    # Add grid
    ax.grid(True, alpha=0.3)
    
    # Add impact level indicators
    impact_levels = [
        (0, 10, "Minimal", "lightblue"),
        (10, 30, "Moderate", "lightyellow"),
        (30, 60, "Severe", "orange"),
        (60, 90, "Critical", "lightcoral"),
        (90, 100, "Catastrophic", "red")
    ]
    
    for min_val, max_val, label, color in impact_levels:
        ax.axhspan(min_val, max_val, alpha=0.2, color=color)
        ax.text(dates[0] - timedelta(days=1), (min_val + max_val) / 2, label, 
               va='center', ha='right', fontsize=8)
    
    # Adjust layout and save
    plt.tight_layout()
    plt.savefig(output_file)
    print(f"Visualization saved to {output_file}")
    
    return output_file


def create_all_visualizations():
    """Create all visualizations and return a list of output files."""
    output_files = []
    
    # Create each visualization
    output_files.append(create_information_loss_visualization())
    output_files.append(create_hash_collision_visualization())
    output_files.append(create_mining_advantage_visualization())
    output_files.append(create_cryptocurrency_collapse_timeline())
    
    return output_files


def main():
    """Run all visualization generation."""
    print("EXISTENCE ONE VISUALIZATIONS")
    print("These visualizations demonstrate the impact of !1 semantics on")
    print("cryptographic systems and digital infrastructure.")
    
    create_all_visualizations()
    
    print("\nAll visualizations generated successfully.")


if __name__ == "__main__":
    main()
