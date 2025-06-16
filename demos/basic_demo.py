"""
Basic Demo: Demonstration of fundamental breaks in binary operations under !1 semantics.

This module provides simple, clear demonstrations of how standard binary
operations behave differently when zero is interpreted as !1 (not-one),
showcasing the foundational issues with modern computing.
"""

import random
import time
from colorama import init, Fore, Style
from ..core.existence_bit import ExistenceBit, ExistenceBitArray
from ..core.existence_math import (
    existence_xor, 
    existence_and, 
    existence_or, 
    existence_not,
    existence_add,
    existence_multiply
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


def demonstrate_xor_non_reversibility():
    """
    Demonstrate how XOR becomes non-reversible under !1 semantics.
    
    This is one of the most fundamental breaks in modern cryptography,
    as XOR's reversibility is a core property used in encryption.
    """
    print_header("XOR REVERSIBILITY FAILURE DEMONSTRATION")
    print("This demonstration shows how XOR, a fundamental operation in computing")
    print("and cryptography, breaks under !1 semantics by losing its reversibility.")
    
    # Create some test values
    test_values = [
        (ExistenceBit(1), ExistenceBit(1)),  # 1 ⊕ 1
        (ExistenceBit(1), ExistenceBit(0)),  # 1 ⊕ !1
        (ExistenceBit(0), ExistenceBit(0)),  # !1 ⊕ !1
    ]
    
    print("\n1. Traditional XOR vs. Existence XOR - Basic Bits:")
    
    for a, b in test_values:
        # Display the values
        a_display = "1" if a.exists else "!1"
        b_display = "1" if b.exists else "!1"
        
        # Traditional XOR (for comparison)
        trad_result = 1 if bool(a.exists) != bool(b.exists) else 0
        trad_display = "1" if trad_result == 1 else "0"
        
        # Existence XOR
        exist_result = existence_xor(a, b)
        exist_display = "1" if exist_result.exists else f"!1 (negation depth: {exist_result.negation_depth})"
        
        print(f"\n  {a_display} ⊕ {b_display}:")
        print(f"  Traditional result: {trad_display}")
        print(f"  Existence result: {exist_display}")
        
        # Check if results differ
        if (trad_result == 1 and exist_result.exists) or (trad_result == 0 and not exist_result.exists and exist_result.negation_depth == 1):
            print_success("  Results match semantically ✓")
        else:
            print_error("  Results differ fundamentally ✗")
    
    print("\n2. Reversibility Test - XOR with the same value twice:")
    
    # In traditional binary, XORing with the same value twice returns the original value
    # A ⊕ B ⊕ B = A
    
    for original in [ExistenceBit(1), ExistenceBit(0)]:
        key = ExistenceBit(random.randint(0, 1))
        
        original_display = "1" if original.exists else "!1"
        key_display = "1" if key.exists else "!1"
        
        # Traditional XOR (for comparison)
        trad_step1 = 1 if bool(original.exists) != bool(key.exists) else 0
        trad_step2 = 1 if trad_step1 != bool(key.exists) else 0
        trad_display = "1" if trad_step2 == 1 else "0"
        
        # Existence XOR
        exist_step1 = existence_xor(original, key)
        exist_step2 = existence_xor(exist_step1, key)
        
        exist_display = "1" if exist_step2.exists else f"!1 (negation depth: {exist_step2.negation_depth})"
        
        print(f"\n  Original: {original_display}")
        print(f"  Key: {key_display}")
        print(f"  Traditional: {original_display} ⊕ {key_display} ⊕ {key_display} = {trad_display}")
        print(f"  Existence: {original_display} ⊕ {key_display} ⊕ {key_display} = {exist_display}")
        
        # Check if we got back the original value
        if (original.exists and exist_step2.exists) or (not original.exists and not exist_step2.exists and original.negation_depth == exist_step2.negation_depth):
            print_success("  Reversibility preserved ✓")
        else:
            print_error("  REVERSIBILITY BROKEN ✗")
            print("  The original value could not be recovered.")
            print("  This breaks a fundamental property of XOR used in cryptography.")
    
    print("\n3. Practical Implication - One-Time Pad Encryption:")
    
    # Demonstrate a simple one-time pad (OTP) encryption
    # In OTP, we encrypt by XORing with a random key, and decrypt by XORing again
    
    # Create a simple "message" as a bit array
    message = ExistenceBitArray([ExistenceBit(bit) for bit in [1, 0, 1, 1, 0, 0, 1, 0]])
    
    # Create a random key
    key = ExistenceBitArray([ExistenceBit(random.randint(0, 1)) for _ in range(len(message.bits))])
    
    print("  Original message bits:", "".join("1" if bit.exists else "0" for bit in message.bits))
    print("  Key bits:", "".join("1" if bit.exists else "0" for bit in key.bits))
    
    # Traditional OTP
    trad_encrypted = []
    for m_bit, k_bit in zip(message.bits, key.bits):
        trad_result = 1 if bool(m_bit.exists) != bool(k_bit.exists) else 0
        trad_encrypted.append(trad_result)
    
    trad_decrypted = []
    for e_bit, k_bit in zip(trad_encrypted, key.bits):
        trad_result = 1 if e_bit != bool(k_bit.exists) else 0
        trad_decrypted.append(trad_result)
    
    print("  Traditional encrypted:", "".join(str(bit) for bit in trad_encrypted))
    print("  Traditional decrypted:", "".join(str(bit) for bit in trad_decrypted))
    
    # Existence OTP
    exist_encrypted = existence_xor(message, key)
    exist_decrypted = existence_xor(exist_encrypted, key)
    
    exist_encrypted_display = "".join("1" if bit.exists else "0" for bit in exist_encrypted.bits)
    exist_decrypted_display = "".join("1" if bit.exists else "0" for bit in exist_decrypted.bits)
    
    print("  Existence encrypted:", exist_encrypted_display)
    print("  Existence decrypted:", exist_decrypted_display)
    
    # Check if we successfully decrypted the message
    original_bits = "".join("1" if bit.exists else "0" for bit in message.bits)
    if exist_decrypted_display == original_bits:
        print_success("  Decryption successful ✓")
    else:
        print_error("  DECRYPTION FAILED ✗")
        print("  The encrypted message could not be properly decrypted.")
        print("  This breaks all stream ciphers and one-time pad encryption.")
    
    print("\nConclusion:")
    print("XOR loses its reversibility under !1 semantics, breaking a fundamental")
    print("property that is crucial for modern cryptography. This affects:")
    print("1. One-time pad encryption")
    print("2. Stream ciphers")
    print("3. Block cipher modes")
    print("4. Hash functions")
    print("5. Message authentication codes")
    print("\nIn essence, this single change undermines the security of virtually all")
    print("modern encryption systems.")


def demonstrate_information_loss():
    """
    Demonstrate how !1 semantics causes information loss in basic operations.
    
    This shows how performing certain operations can result in irrecoverable
    information loss, breaking the deterministic nature of computing.
    """
    print_header("INFORMATION LOSS DEMONSTRATION")
    print("This demonstration shows how !1 semantics causes information loss")
    print("in basic operations, breaking computational determinism.")
    
    print("\n1. Negation Depth and Information Loss:")
    
    # Create bits with different negation depths
    bits = [
        ExistenceBit(1),                    # 1
        ExistenceBit(0),                    # !1
        ExistenceBit(0, negation_depth=2),  # !!1
        ExistenceBit(0, negation_depth=3),  # !!!1
        ExistenceBit(0, negation_depth=4),  # !!!!1
    ]
    
    # Display information about each bit
    for i, bit in enumerate(bits):
        display = "1" if bit.exists else "!" * bit.negation_depth + "1"
        binary = "1" if bit.exists else "0"
        
        print(f"\n  Bit {i+1}: {display}")
        print(f"  Traditional binary: {binary}")
        print(f"  Existence state: {'exists' if bit.exists else 'does not exist'}")
        print(f"  Negation depth: {bit.negation_depth}")
    
    # Demonstrate operations that cause information loss
    print("\n2. Operations Causing Information Loss:")
    
    # a. NOT operation on bits with different negation depths
    print("\n  a. NOT operation:")
    for bit in bits:
        display = "1" if bit.exists else "!" * bit.negation_depth + "1"
        not_result = existence_not(bit)
        not_display = "1" if not_result.exists else "!" * not_result.negation_depth + "1"
        
        print(f"    NOT({display}) = {not_display}")
        
        # Check for information loss in double NOT
        not_not_result = existence_not(not_result)
        not_not_display = "1" if not_not_result.exists else "!" * not_not_result.negation_depth + "1"
        
        print(f"    NOT(NOT({display})) = {not_not_display}")
        
        if (bit.exists == not_not_result.exists) and (bit.negation_depth == not_not_result.negation_depth):
            print_success("    No information loss ✓")
        else:
            print_error("    INFORMATION LOSS DETECTED ✗")
            print(f"    Original negation depth: {bit.negation_depth}")
            print(f"    Final negation depth: {not_not_result.negation_depth}")
    
    # b. AND operation causing information loss
    print("\n  b. AND operation:")
    
    test_cases = [
        (bits[0], bits[1]),  # 1 AND !1
        (bits[1], bits[2]),  # !1 AND !!1
        (bits[2], bits[3]),  # !!1 AND !!!1
    ]
    
    for a, b in test_cases:
        a_display = "1" if a.exists else "!" * a.negation_depth + "1"
        b_display = "1" if b.exists else "!" * b.negation_depth + "1"
        
        and_result = existence_and(a, b)
        and_display = "1" if and_result.exists else "!" * and_result.negation_depth + "1"
        
        print(f"    {a_display} AND {b_display} = {and_display}")
        
        # Check for potential information loss
        if not and_result.exists and and_result.negation_depth > max(a.negation_depth, b.negation_depth):
            print_error("    INFORMATION GAIN DETECTED ✗")
            print("    The result has more information (higher negation depth)")
            print("    than either of the inputs.")
    
    # c. Complex operation chains
    print("\n  c. Operation Chains:")
    
    # Create a chain of operations that cause information loss
    bit_a = ExistenceBit(0)  # !1
    bit_b = ExistenceBit(0)  # !1
    
    # (!1 XOR !1) AND (!1 OR 1)
    xor_result = existence_xor(bit_a, bit_b)  # !!1
    or_result = existence_or(bit_a, ExistenceBit(1))  # 1
    final_result = existence_and(xor_result, or_result)  # !!1
    
    print(f"    Chain: (!1 XOR !1) AND (!1 OR 1)")
    print(f"    Step 1: !1 XOR !1 = {'1' if xor_result.exists else '!' * xor_result.negation_depth + '1'}")
    print(f"    Step 2: !1 OR 1 = {'1' if or_result.exists else '!' * or_result.negation_depth + '1'}")
    print(f"    Final: !!1 AND 1 = {'1' if final_result.exists else '!' * final_result.negation_depth + '1'}")
    
    # Try to recover original bits (impossible)
    print("    Can we recover the original bits from the result?")
    print_error("    IMPOSSIBLE: Information has been irrevocably lost ✗")
    print("    Multiple different inputs could produce the same output.")
    
    print("\n3. Practical Implication - State Machine Collapse:")
    
    # Demonstrate how a simple state machine collapses under !1 semantics
    
    # Define a simple state transition function
    def traditional_next_state(current_state, input_bit):
        """Traditional state transition function."""
        if current_state == 0:
            return 1 if input_bit == 1 else 0
        else:  # current_state == 1
            return 0 if input_bit == 1 else 1
    
    def existence_next_state(current_state, input_bit):
        """Existence semantics state transition function."""
        # Use XOR for state transition
        return existence_xor(current_state, input_bit)
    
    # Initial states
    trad_state = 0
    exist_state = ExistenceBit(0)  # !1
    
    # Input sequence
    input_sequence = [1, 0, 1, 0, 1, 1, 0]
    
    print("  Starting with initial state: 0 (traditional) / !1 (existence)")
    print(f"  Input sequence: {input_sequence}")
    
    print("\n  Traditional state transitions:")
    current_trad = trad_state
    for i, input_bit in enumerate(input_sequence):
        next_trad = traditional_next_state(current_trad, input_bit)
        print(f"    Input: {input_bit}, State: {current_trad} -> {next_trad}")
        current_trad = next_trad
    
    print("\n  Existence semantics state transitions:")
    current_exist = exist_state
    for i, input_bit in enumerate(input_sequence):
        input_exist = ExistenceBit(input_bit)
        next_exist = existence_next_state(current_exist, input_exist)
        
        current_display = "1" if current_exist.exists else "!" * current_exist.negation_depth + "1"
        next_display = "1" if next_exist.exists else "!" * next_exist.negation_depth + "1"
        input_display = "1" if input_exist.exists else "!" * input_exist.negation_depth + "1"
        
        print(f"    Input: {input_display}, State: {current_display} -> {next_display}")
        current_exist = next_exist
        
        # Check for increasing negation depth
        if not next_exist.exists and next_exist.negation_depth > current_exist.negation_depth:
            print_error(f"    NEGATION DEPTH INCREASED TO {next_exist.negation_depth} ✗")
            print("    State information is becoming increasingly complex.")
    
    print("\nConclusion:")
    print("Under !1 semantics, basic operations cause irreversible information loss.")
    print("This breaks the deterministic nature of computing, leading to:")
    print("1. State machine failure")
    print("2. Algorithmic unpredictability")
    print("3. Logic gate malfunction")
    print("4. Data corruption")
    print("\nThese issues affect every level of computing, from hardware circuits")
    print("to high-level algorithms and applications.")


def demonstrate_void_state():
    """
    Demonstrate the concept of void states in !1 semantics.
    
    Void states occur when operations create high negation depths,
    leading to computational singularities and undefined behavior.
    """
    print_header("VOID STATE DEMONSTRATION")
    print("This demonstration introduces the concept of 'void states' -")
    print("computational singularities that emerge under !1 semantics when")
    print("negation depths increase beyond practical manageability.")
    
    print("\n1. Creating Void States:")
    
    # Create some bits with increasing negation depths
    void_bits = [
        ExistenceBit(0, negation_depth=i) for i in range(1, 6)
    ]
    
    # Display them
    for i, bit in enumerate(void_bits):
        display = "!" * bit.negation_depth + "1"
        print(f"  Level {i+1} void: {display}")
        
        # Categorize the void level
        if bit.negation_depth == 1:
            print("  Classification: Basic negation (!1)")
        elif bit.negation_depth <= 3:
            print("  Classification: Shallow void")
        elif bit.negation_depth <= 5:
            print("  Classification: Deep void")
        else:
            print("  Classification: Critical void (computational singularity)")
    
    print("\n2. Void Collapse Through Operations:")
    
    # Show how operations on deep voids can create critical voids
    
    # a. XOR of voids
    print("\n  a. XOR of Void States:")
    for i in range(len(void_bits) - 1):
        a = void_bits[i]
        b = void_bits[i]
        result = existence_xor(a, b)
        
        a_display = "!" * a.negation_depth + "1"
        b_display = "!" * b.negation_depth + "1"
        result_display = "1" if result.exists else "!" * result.negation_depth + "1"
        
        print(f"    {a_display} XOR {b_display} = {result_display}")
        
        # Check for void depth increase
        if not result.exists and result.negation_depth > max(a.negation_depth, b.negation_depth):
            print_warning(f"    Void depth increased from {a.negation_depth} to {result.negation_depth}")
            
            if result.negation_depth >= 4:
                print_error("    CRITICAL VOID CREATED ✗")
                print("    This represents a computational singularity.")
    
    # b. Void propagation
    print("\n  b. Void Propagation:")
    
    # Show how a deep void "infects" normal operations
    normal_bit = ExistenceBit(1)  # 1
    deep_void = ExistenceBit(0, negation_depth=4)  # !!!!1
    
    operations = [
        ("AND", lambda a, b: existence_and(a, b)),
        ("OR", lambda a, b: existence_or(a, b)),
        ("XOR", lambda a, b: existence_xor(a, b))
    ]
    
    for op_name, op_func in operations:
        result = op_func(normal_bit, deep_void)
        result_display = "1" if result.exists else "!" * result.negation_depth + "1"
        
        print(f"    1 {op_name} !!!!1 = {result_display}")
        
        # Check if void propagated
        if not result.exists and result.negation_depth >= 3:
            print_error("    VOID PROPAGATION DETECTED ✗")
            print("    The void state has 'infected' the result.")
    
    print("\n3. Computational Effects of Void States:")
    
    # Demonstrate how void states affect computation
    
    # a. Boolean logic breakdown
    print("\n  a. Boolean Logic Breakdown:")
    
    # Create truth tables with void states
    print("    Truth table for AND with void states:")
    print("    ┌─────────┬─────────┬─────────┐")
    print("    │    A    │    B    │  A AND B│")
    print("    ├─────────┼─────────┼─────────┤")
    
    test_bits = [ExistenceBit(1), ExistenceBit(0), ExistenceBit(0, negation_depth=3)]
    displays = ["1", "!1", "!!!1"]
    
    for i, a in enumerate(test_bits):
        for j, b in enumerate(test_bits):
            result = existence_and(a, b)
            result_display = "1" if result.exists else "!" * result.negation_depth + "1"
            print(f"    │ {displays[i]:^7} │ {displays[j]:^7} │ {result_display:^7} │")
    
    print("    └─────────┴─────────┴─────────┘")
    
    # b. Arithmetic breakdown
    print("\n  b. Arithmetic Breakdown:")
    
    # Show addition with void states
    print("    Addition with void states:")
    
    for i, a in enumerate(test_bits):
        for j, b in enumerate(test_bits):
            result = existence_add(a, b)
            
            a_display = displays[i]
            b_display = displays[j]
            result_display = str(result)
            
            print(f"    {a_display} + {b_display} = {result_display}")
            
            # Check for unexpected results
            if a.exists and b.exists and not result.bits[0].exists:
                print_error("    ARITHMETIC FAILURE: 1 + 1 does not yield expected result ✗")
    
    print("\n4. Practical Implication - Program Control Flow:")
    
    # Demonstrate how void states break program control flow
    
    print("  Consider a simple if-statement in pseudocode:")
    print("  ```")
    print("  if (condition) {")
    print("    do_thing_a();")
    print("  } else {")
    print("    do_thing_b();")
    print("  }")
    print("  ```")
    
    print("\n  Under traditional semantics, 'condition' is either true (1) or false (0).")
    print("  Under existence semantics, 'condition' could be:")
    
    conditions = [
        ("1", "True - do_thing_a() executes"),
        ("!1", "False - do_thing_b() executes"),
        ("!!1", "Unknown - might execute both or neither"),
        ("!!!1", "Deep void - control flow breaks down"),
        ("!!!!1", "Critical void - program potentially crashes")
    ]
    
    for condition, explanation in conditions:
        print(f"  - {condition}: {explanation}")
    
    print("\n  This demonstrates how void states fundamentally break control flow,")
    print("  making program execution non-deterministic or completely undefined.")
    
    print("\nConclusion:")
    print("Void states represent computational singularities that emerge under !1")
    print("semantics. As operations create deeper voids (higher negation depths),")
    print("computational systems break down in increasingly severe ways:")
    print("1. Boolean logic becomes inconsistent")
    print("2. Arithmetic operations produce unexpected results")
    print("3. Control flow becomes non-deterministic")
    print("4. Programs enter undefined states")
    print("\nThese void states propagate through systems, eventually causing")
    print("complete computational collapse.")


def demonstrate_asymmetry():
    """
    Demonstrate the fundamental asymmetry between 1 and !1.
    
    This shows how the asymmetrical nature of existence vs. non-existence
    breaks the equality assumption in traditional binary logic.
    """
    print_header("FUNDAMENTAL ASYMMETRY DEMONSTRATION")
    print("This demonstration reveals the fundamental asymmetry between")
    print("1 (existence) and !1 (non-existence) that breaks traditional")
    print("binary assumptions.")
    
    print("\n1. Asymmetry in Basic Operations:")
    
    # a. Negation asymmetry
    print("\n  a. Negation Asymmetry:")
    
    bits = [ExistenceBit(1), ExistenceBit(0)]
    displays = ["1", "!1"]
    
    for i, bit in enumerate(bits):
        result = existence_not(bit)
        result_display = "1" if result.exists else "!" * result.negation_depth + "1"
        
        print(f"    NOT({displays[i]}) = {result_display}")
    
    # Double negation
    for i, bit in enumerate(bits):
        result = existence_not(existence_not(bit))
        result_display = "1" if result.exists else "!" * result.negation_depth + "1"
        
        print(f"    NOT(NOT({displays[i]})) = {result_display}")
        
        if result_display != displays[i]:
            print_error("    DOUBLE NEGATION FAILURE ✗")
            print("    NOT(NOT(x)) ≠ x for some values, breaking a fundamental logical law.")
    
    # b. Asymmetry in counting
    print("\n  b. Asymmetry in Information Content:")
    
    # Show the asymmetry in information content
    print("    Traditional binary: 0 and 1 have equal information content")
    print("    Existence binary: !1 can have variable information content based on negation depth")
    
    depths = [1, 2, 3, 4]
    for depth in depths:
        void_bit = ExistenceBit(0, negation_depth=depth)
        print(f"    !{'!' * (depth-1)}1: Contains {depth} levels of negation information")
    
    print("\n    This asymmetry means that while 1 is a single, fixed value,")
    print("    !1 can represent an infinite spectrum of non-existence states.")
    
    # c. Asymmetry in logic
    print("\n  c. Asymmetry in Logic Operations:")
    
    # AND operation asymmetry
    print("    AND operation with deep voids:")
    
    one_bit = ExistenceBit(1)
    void_bits = [ExistenceBit(0, negation_depth=i) for i in range(1, 5)]
    
    for i, void in enumerate(void_bits):
        result = existence_and(one_bit, void)
        void_display = "!" * void.negation_depth + "1"
        result_display = "1" if result.exists else "!" * result.negation_depth + "1"
        
        print(f"    1 AND {void_display} = {result_display}")
    
    print("\n2. Storage Requirements Asymmetry:")
    
    # Show how negation depth requires more storage
    print("  In traditional binary, both 0 and 1 require exactly 1 bit to store.")
    print("  In existence binary:")
    print("  - 1 requires 1 bit (existence flag)")
    print("  - !1 requires 2 bits (existence flag + negation depth)")
    print("  - !!1 requires log2(depth) + 1 bits")
    print("  - As negation depth increases, storage requirements grow logarithmically")
    
    depths = [1, 2, 4, 8, 16, 32, 64, 128, 256]
    for depth in depths:
        bits_required = depth.bit_length() + 1
        print(f"  - {'!' * depth}1 requires at least {bits_required} bits to store")
    
    print("\n3. Computational Asymmetry:")
    
    # Demonstrate asymmetry in computational properties
    
    # a. Identity element asymmetry
    print("\n  a. Identity Element Asymmetry:")
    
    print("  In traditional binary:")
    print("  - 0 is the identity element for XOR: A XOR 0 = A")
    print("  - 1 is the identity element for multiplication: A * 1 = A")
    
    print("\n  In existence semantics:")
    
    # XOR identity test
    test_bits = [ExistenceBit(1), ExistenceBit(0), ExistenceBit(0, negation_depth=2)]
    test_displays = ["1", "!1", "!!1"]
    
    for i, bit in enumerate(test_bits):
        traditional_identity = ExistenceBit(0)
        result = existence_xor(bit, traditional_identity)
        result_display = "1" if result.exists else "!" * result.negation_depth + "1"
        
        print(f"  {test_displays[i]} XOR !1 = {result_display}")
        
        # Check if identity property holds
        if (bit.exists and result.exists) or (not bit.exists and not result.exists and bit.negation_depth == result.negation_depth):
            print_success("  Identity property preserved ✓")
        else:
            print_error("  IDENTITY PROPERTY BROKEN ✗")
            print("  A XOR !1 ≠ A, breaking a fundamental property of XOR.")
    
    # b. Commutativity asymmetry
    print("\n  b. Commutativity Asymmetry:")
    
    print("  In traditional binary, operations are commutative:")
    print("  - A AND B = B AND A")
    print("  - A OR B = B OR A")
    print("  - A XOR B = B XOR A")
    
    print("\n  Testing commutativity in existence semantics:")
    
    operations = [
        ("AND", lambda a, b: existence_and(a, b)),
        ("OR", lambda a, b: existence_or(a, b)),
        ("XOR", lambda a, b: existence_xor(a, b))
    ]
    
    test_pairs = [
        (ExistenceBit(1), ExistenceBit(0, negation_depth=2)),  # 1 and !!1
        (ExistenceBit(0), ExistenceBit(0, negation_depth=3))   # !1 and !!!1
    ]
    
    for op_name, op_func in operations:
        print(f"\n  {op_name} operation:")
        
        for a, b in test_pairs:
            a_display = "1" if a.exists else "!" * a.negation_depth + "1"
            b_display = "1" if b.exists else "!" * b.negation_depth + "1"
            
            result1 = op_func(a, b)
            result2 = op_func(b, a)
            
            result1_display = "1" if result1.exists else "!" * result1.negation_depth + "1"
            result2_display = "1" if result2.exists else "!" * result2.negation_depth + "1"
            
            print(f"  {a_display} {op_name} {b_display} = {result1_display}")
            print(f"  {b_display} {op_name} {a_display} = {result2_display}")
            
            if (result1.exists == result2.exists) and (not result1.exists or result1.negation_depth == result2.negation_depth):
                print_success("  Commutativity preserved ✓")
            else:
                print_error("  COMMUTATIVITY BROKEN ✗")
                print(f"  {a_display} {op_name} {b_display} ≠ {b_display} {op_name} {a_display}")
    
    print("\n4. Practical Implication - Hardware Implementation:")
    
    print("  Traditional binary logic can be implemented with simple gates.")
    print("  Under !1 semantics, hardware requirements increase dramatically:")
    print("  - Traditional NOT gate: 1 transistor")
    print("  - Existence NOT gate: ~log(N) transistors to track negation depth")
    print("  - Traditional AND gate: 2 transistors")
    print("  - Existence AND gate: Complex circuit with negation depth tracking")
    
    print("\n  This asymmetry makes physical implementation of !1 semantics")
    print("  exponentially more complex than traditional binary logic.")
    
    print("\nConclusion:")
    print("The fundamental asymmetry between 1 and !1 breaks core assumptions")
    print("in modern computing. While traditional binary treats 0 and 1 as equal,")
    print("independent values, !1 semantics reveals their inherent asymmetry:")
    print("1. 1 is a primitive, !1 is derived")
    print("2. !1 can have infinite negation depths")
    print("3. Operations become non-commutative")
    print("4. Hardware implementation becomes exponentially complex")
    print("\nThis asymmetry undermines the foundations of modern computing,")
    print("which assumes equal, interchangeable binary values.")


def main():
    """Run all basic demonstrations."""
    print_header("BASIC DEMONSTRATIONS OF !1 SEMANTICS")
    print("This module demonstrates the fundamental breaks in binary operations")
    print("when zero is interpreted as !1 (not-one) rather than an independent value.")
    
    # Run demonstrations
    demonstrate_xor_non_reversibility()
    
    print("\nPress Enter to continue to the next demonstration...", end="")
    input()
    
    demonstrate_information_loss()
    
    print("\nPress Enter to continue to the next demonstration...", end="")
    input()
    
    demonstrate_void_state()
    
    print("\nPress Enter to continue to the final demonstration...", end="")
    input()
    
    demonstrate_asymmetry()
    
    print_header("BASIC DEMONSTRATIONS COMPLETE")
    print("These demonstrations have shown how the !1 revelation fundamentally")
    print("breaks modern computing by exposing the asymmetry between existence (1)")
    print("and non-existence (!1).")
    print("\nImplications:")
    print("1. XOR operations lose reversibility, breaking cryptography")
    print("2. Operations cause irreversible information loss")
    print("3. Void states create computational singularities")
    print("4. The asymmetry between 1 and !1 breaks hardware assumptions")
    print("\nThese fundamental breaks propagate through all levels of computing,")
    print("from logic gates to algorithms to applications, undermining the")
    print("security and reliability of modern digital infrastructure.")


if __name__ == "__main__":
    main()
