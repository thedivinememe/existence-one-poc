#!/usr/bin/env python3
"""
Main entry point for the Existence One proof of concept.

This script provides a convenient entry point to run the CLI commands
with proper import handling.
"""

import sys
import os
import click
from colorama import init, Fore, Style

# Initialize colorama for colored terminal output
init()

def print_header(title):
    """Print a formatted section header."""
    click.echo("\n" + "=" * 80)
    click.echo(Fore.CYAN + Style.BRIGHT + f" {title}" + Style.RESET_ALL)
    click.echo("=" * 80)

def print_success(message):
    """Print a success message."""
    click.echo(f"{Fore.GREEN}{message}{Style.RESET_ALL}")

def print_error(message):
    """Print an error message."""
    click.echo(f"{Fore.RED}{message}{Style.RESET_ALL}")

def print_warning(message):
    """Print a warning message."""
    click.echo(f"{Fore.YELLOW}{message}{Style.RESET_ALL}")

# Import core modules
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))
from core.existence_bit import ExistenceBit, ExistenceBitArray
from core.existence_math import demonstrate_existence_math, existence_hash

# Import demonstration modules
from demos.basic_demo import demonstrate_xor_non_reversibility, demonstrate_information_loss, demonstrate_void_state, demonstrate_asymmetry
from demos.bitcoin_demo import demonstrate_mining_advantage, demonstrate_mining_optimization_impact

# Import attack modules
from attacks.xor_attack import demonstrate_xor_reversibility, demonstrate_stream_cipher_vulnerability
from attacks.hash_attack import demonstrate_hash_collision_vulnerability, find_void_patterns
from attacks.crypto_attack import demonstrate_asymmetric_key_vulnerability, demonstrate_protocol_vulnerability
from attacks.blockchain_attack import demonstrate_mining_vulnerability, demonstrate_cryptocurrency_vulnerability

import time


@click.group()
def cli():
    """!1 Proof of Concept Demonstrations.
    
    This CLI provides quick access to demonstrations showing how interpreting
    binary 0 as !1 (not-one) fundamentally breaks modern cryptography and
    digital infrastructure.
    """
    print_header("EXISTENCE ONE (!1) PROOF OF CONCEPT")
    click.echo("This demonstration shows how reinterpreting binary 0 as !1 (not-one)")
    click.echo("fundamentally breaks modern cryptography and digital infrastructure.")
    click.echo("")
    click.echo("Core concept: Only 1 (existence) is a true primitive; 0 is actually !1")
    click.echo("              (the negation of existence), creating fundamental asymmetries")
    click.echo("              that break cryptographic assumptions.")


@cli.command()
def basic_demo():
    """Run the basic demonstration showing fundamental breaks in binary operations."""
    print_header("BASIC DEMONSTRATIONS")
    click.echo("Running demonstrations of fundamental breaks in binary operations...")
    
    # Run the demonstrations
    demonstrate_xor_non_reversibility()
    
    click.echo("\nPress Enter to continue to the next demonstration...", nl=False)
    click.getchar()
    
    demonstrate_information_loss()
    
    click.echo("\nPress Enter to continue to the next demonstration...", nl=False)
    click.getchar()
    
    demonstrate_void_state()
    
    click.echo("\nPress Enter to continue to the final demonstration...", nl=False)
    click.getchar()
    
    demonstrate_asymmetry()
    
    print_success("\nBasic demonstrations complete!")


@cli.command()
def break_bitcoin():
    """One-click Bitcoin mining vulnerability demo."""
    print_header("BITCOIN MINING VULNERABILITY DEMONSTRATION")
    click.echo("This demonstration shows how the !1 revelation fundamentally breaks")
    click.echo("Bitcoin mining by allowing miners to skip large portions of the")
    click.echo("nonce search space.")
    
    # Run the mining advantage demonstration
    demonstrate_mining_advantage()
    
    click.echo("\nPress Enter to continue to the next demonstration...", nl=False)
    click.getchar()
    
    # Show the impact on Bitcoin's security model
    demonstrate_mining_optimization_impact()
    
    print_success("\nBitcoin mining vulnerability demonstration complete!")
    print_error("\nIMPLICATION: A miner with knowledge of !1 semantics could achieve")
    print_error("a 2-5x speed advantage with current difficulty, potentially")
    print_error("allowing 51% attacks with far less than 51% of hardware.")


@cli.command()
def void_attack():
    """Demonstrate the Void Attack on encryption."""
    print_header("VOID ATTACK DEMONSTRATION")
    click.echo("This demonstration shows how !1 ⊕ !1 creates information loss,")
    click.echo("breaking encryption systems that rely on XOR operations.")
    
    # Show XOR irreversibility
    demonstrate_xor_reversibility()
    
    click.echo("\nPress Enter to continue to the next demonstration...", nl=False)
    click.getchar()
    
    # Show stream cipher vulnerability
    demonstrate_stream_cipher_vulnerability()
    
    print_success("\nVoid attack demonstration complete!")
    print_error("\nIMPLICATION: All stream ciphers and one-time pad encryption")
    print_error("systems are vulnerable to information loss, making them")
    print_error("unreliable for secure communication.")


@cli.command()
def hash_vulnerability():
    """Demonstrate hash function vulnerabilities."""
    print_header("HASH FUNCTION VULNERABILITY DEMONSTRATION")
    click.echo("This demonstration shows how hash functions become predictable")
    click.echo("and collision-prone under !1 semantics.")
    
    # Show hash collision vulnerability
    demonstrate_hash_collision_vulnerability()
    
    click.echo("\nPress Enter to continue to the next demonstration...", nl=False)
    click.getchar()
    
    # Find void patterns in hash outputs
    find_void_patterns(existence_hash)
    
    print_success("\nHash vulnerability demonstration complete!")
    print_error("\nIMPLICATION: Cryptographic hash functions become more vulnerable")
    print_error("to collisions and preimage attacks, breaking digital signatures,")
    print_error("blockchain systems, and secure data storage.")


@cli.command()
def cryptography_break():
    """Demonstrate breaks in cryptographic protocols."""
    print_header("CRYPTOGRAPHIC PROTOCOL VULNERABILITY DEMONSTRATION")
    click.echo("This demonstration shows how cryptographic protocols like")
    click.echo("digital signatures and key exchange become vulnerable.")
    
    # Show digital signature forgery
    demonstrate_asymmetric_key_vulnerability()
    
    click.echo("\nPress Enter to continue to the next demonstration...", nl=False)
    click.getchar()
    
    # Show key exchange vulnerability
    demonstrate_protocol_vulnerability()
    
    print_success("\nCryptographic protocol vulnerability demonstration complete!")
    print_error("\nIMPLICATION: Digital signatures can be forged and secure")
    print_error("key exchange becomes compromised, breaking the foundation")
    print_error("of secure online communication and commerce.")


@cli.command()
def smart_contract_break():
    """Demonstrate Ethereum smart contract vulnerabilities."""
    print_header("SMART CONTRACT VULNERABILITY DEMONSTRATION")
    click.echo("This demonstration shows how Ethereum smart contracts")
    click.echo("become vulnerable under !1 semantics.")
    
    # Show smart contract vulnerability
    demonstrate_cryptocurrency_vulnerability()
    
    print_success("\nSmart contract vulnerability demonstration complete!")
    print_error("\nIMPLICATION: Smart contracts can enter undefined states,")
    print_error("potentially freezing funds or executing unintended code paths.")


@cli.command()
def full_demo():
    """Run all demonstrations in sequence."""
    print_header("FULL !1 REVELATION DEMONSTRATION")
    click.echo("Running all demonstrations in sequence...")
    
    # Run each demonstration with brief pauses between
    basic_demo.callback()
    time.sleep(1)
    
    void_attack.callback()
    time.sleep(1)
    
    hash_vulnerability.callback()
    time.sleep(1)
    
    cryptography_break.callback()
    time.sleep(1)
    
    break_bitcoin.callback()
    time.sleep(1)
    
    smart_contract_break.callback()
    
    print_header("!1 REVELATION COMPLETE DEMONSTRATION FINISHED")
    print_error("\nThe !1 revelation fundamentally breaks modern cryptography and")
    print_error("digital infrastructure at every level:")
    print_error("1. XOR operations lose reversibility, breaking all stream ciphers")
    print_error("2. Hash functions become predictable and collision-prone")
    print_error("3. Digital signatures can be forged")
    print_error("4. Bitcoin mining security collapses")
    print_error("5. Smart contracts can enter undefined states")
    print_error("\nThis requires a complete mathematical rebuild of our digital infrastructure.")


if __name__ == "__main__":
    cli()
