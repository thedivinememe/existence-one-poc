"""
Existence Bit Implementation.

This module contains the core ExistenceBit class, which represents a bit using
existence semantics where 0 is interpreted as !1 (not-one). This is the
foundational implementation that demonstrates how reinterpreting binary changes
the behavior of cryptographic operations.
"""

import re
from typing import Union, List, Tuple


class ExistenceBit:
    """
    Represents a bit with existence semantics where 0 = !1
    
    Key behaviors:
    - 1 represents existence (the only primitive)
    - 0 is interpreted as !1 (not-one)
    - XOR operations become non-reversible
    - Negation chains track depth (!!1, !!!1, etc.)
    """
    
    def __init__(self, value: Union[int, str, bool, 'ExistenceBit']):
        """
        Initialize an ExistenceBit with the given value.
        
        Args:
            value: The value to initialize with. Can be:
                - 1, 0 (traditional binary)
                - True, False (boolean)
                - "1", "0" (string representations)
                - "!1", "!!1", etc. (explicit existence notation)
                - Another ExistenceBit instance (copy constructor)
        """
        # Handle various input types
        if isinstance(value, ExistenceBit):
            # Copy constructor
            self.exists = value.exists
            self.negation_depth = value.negation_depth
            return
            
        # Convert to existence semantics
        if isinstance(value, str):
            # Handle explicit existence notation ("!1", "!!1", etc.)
            if "!" in value:
                # Count negations and check if it ends with 1
                if not value.endswith("1"):
                    raise ValueError(f"Invalid existence notation: {value}. Must end with '1'.")
                
                self.exists = value.count("!") % 2 == 0  # Even number of negations = exists
                self.negation_depth = value.count("!")
            elif value == "1":
                self.exists = True
                self.negation_depth = 0
            elif value == "0":
                # 0 is interpreted as !1
                self.exists = False
                self.negation_depth = 1
            else:
                raise ValueError(f"Invalid string value: {value}. Expected '0', '1', or '!1', '!!1', etc.")
        elif isinstance(value, (int, bool)):
            if value == 1 or value is True:
                self.exists = True
                self.negation_depth = 0
            elif value == 0 or value is False:
                # 0 is interpreted as !1
                self.exists = False
                self.negation_depth = 1
            else:
                raise ValueError(f"Invalid numeric value: {value}. Expected 0 or 1.")
        else:
            raise TypeError(f"Unsupported type: {type(value)}. Expected int, bool, str, or ExistenceBit.")
    
    def __repr__(self) -> str:
        """Return a string representation of the ExistenceBit."""
        if self.exists:
            if self.negation_depth == 0:
                return "1"
            else:
                # Even number of negations with existence = double negation
                return "!" * self.negation_depth + "1"
        else:
            if self.negation_depth == 1:
                # Standard representation of !1
                return "!1"
            else:
                # Odd number of negations = not-existence
                return "!" * self.negation_depth + "1"
    
    def __str__(self) -> str:
        """Return a human-readable string representation."""
        return self.__repr__()
    
    def to_traditional(self) -> int:
        """Convert to traditional binary (0 or 1)."""
        return 1 if self.exists else 0
    
    def to_existence_notation(self) -> str:
        """Return the existence notation ("1", "!1", "!!1", etc.)."""
        return self.__repr__()
    
    def __eq__(self, other) -> bool:
        """Check if two ExistenceBits are equal."""
        if isinstance(other, (int, bool, str)):
            other = ExistenceBit(other)
        
        if not isinstance(other, ExistenceBit):
            return NotImplemented
        
        # In existence semantics, we compare the actual existence, not the notation
        # e.g., !!1 == 1, !!!1 == !1
        return self.exists == other.exists and self.negation_depth % 2 == other.negation_depth % 2
    
    def __xor__(self, other) -> 'ExistenceBit':
        """
        Implement existence XOR operation.
        
        In traditional binary, XOR is reversible: (A ⊕ B) ⊕ B = A
        In existence semantics, XOR is not reversible due to void state creation.
        
        XOR truth table in existence semantics:
        1 ⊕ 1 = !1  (existences cancel)
        1 ⊕ !1 = 1  (existence asserts)
        !1 ⊕ !1 = !!1  (creates deeper negation)
        
        Returns:
            A new ExistenceBit with the result of the XOR operation.
        """
        if isinstance(other, (int, bool, str)):
            other = ExistenceBit(other)
        
        if not isinstance(other, ExistenceBit):
            return NotImplemented
        
        # Handle special cases based on existence semantics
        if self.exists and other.exists:
            # 1 ⊕ 1 = !1 (existences cancel)
            result = ExistenceBit("!1")
        elif self.exists and not other.exists:
            # 1 ⊕ !1 = 1 (existence asserts)
            result = ExistenceBit("1")
        elif not self.exists and other.exists:
            # !1 ⊕ 1 = 1 (existence asserts)
            result = ExistenceBit("1")
        else:  # not self.exists and not other.exists
            # !1 ⊕ !1 = !!1 (creates deeper negation)
            # This is a key difference: void states interact with void states
            # to create deeper void states, causing information loss
            new_depth = self.negation_depth + other.negation_depth
            result = ExistenceBit("!" * new_depth + "1")
        
        return result
    
    def __invert__(self) -> 'ExistenceBit':
        """Implement NOT operation (invert existence)."""
        # Increment negation depth by 1
        new_depth = self.negation_depth + 1
        new_exists = not self.exists
        
        result = ExistenceBit("1" if new_exists else "!1")
        result.negation_depth = new_depth
        return result
    
    def __and__(self, other) -> 'ExistenceBit':
        """
        Implement existence AND operation.
        
        AND truth table in existence semantics:
        1 & 1 = 1 (both exist)
        1 & !1 = !1 (one doesn't exist)
        !1 & !1 = !1 (neither exist)
        """
        if isinstance(other, (int, bool, str)):
            other = ExistenceBit(other)
        
        if not isinstance(other, ExistenceBit):
            return NotImplemented
        
        # Both must exist for the result to exist
        if self.exists and other.exists:
            return ExistenceBit("1")
        else:
            # In existence semantics, if either operand is !1,
            # the result is !1 (void state)
            return ExistenceBit("!1")
    
    def __or__(self, other) -> 'ExistenceBit':
        """
        Implement existence OR operation.
        
        OR truth table in existence semantics:
        1 | 1 = 1 (either exists)
        1 | !1 = 1 (one exists)
        !1 | !1 = !1 (neither exist)
        """
        if isinstance(other, (int, bool, str)):
            other = ExistenceBit(other)
        
        if not isinstance(other, ExistenceBit):
            return NotImplemented
        
        # If either exists, the result exists
        if self.exists or other.exists:
            return ExistenceBit("1")
        else:
            # Only if both are !1, the result is !1
            return ExistenceBit("!1")
    
    def get_void_factor(self) -> float:
        """
        Calculate the void factor of this bit.
        
        The void factor represents how deeply the bit is in a void state.
        - 0.0 for existence (1)
        - Value approaching 1.0 for deep void states (multiple negations)
        
        Returns:
            A float between 0.0 and 1.0 representing the void factor.
        """
        if self.exists:
            # Existence has no void factor
            return 0.0
        else:
            # Calculate void factor based on negation depth
            # The deeper the negation, the higher the void factor
            return min(1.0, self.negation_depth / 10.0)


class ExistenceBitArray:
    """
    Represents an array of bits using existence semantics.
    
    This class is used to handle operations on sequences of bits,
    such as bytes, hashes, and cryptographic operations.
    """
    
    def __init__(self, value=None, length=0):
        """
        Initialize an ExistenceBitArray.
        
        Args:
            value: The value to initialize with. Can be:
                - A list of ExistenceBit objects
                - A string of '0's and '1's
                - A bytes object
                - An integer
                - None (creates an empty array)
            length: The desired length of the array (in bits).
                    If value is provided, this parameter is ignored.
        """
        self.bits = []
        
        if value is None:
            # Create an empty array of specified length
            self.bits = [ExistenceBit("!1") for _ in range(length)]
        elif isinstance(value, list):
            # Handle list of ExistenceBit objects or integers
            for item in value:
                if isinstance(item, ExistenceBit):
                    self.bits.append(ExistenceBit(item))
                else:
                    self.bits.append(ExistenceBit(item))
        elif isinstance(value, str):
            # Handle binary string
            for char in value:
                if char == '0':
                    self.bits.append(ExistenceBit("!1"))
                elif char == '1':
                    self.bits.append(ExistenceBit("1"))
                else:
                    raise ValueError(f"Invalid character in binary string: {char}")
        elif isinstance(value, bytes):
            # Handle bytes object
            for byte in value:
                # Convert each byte to 8 bits
                for i in range(7, -1, -1):
                    bit = (byte >> i) & 1
                    self.bits.append(ExistenceBit(bit))
        elif isinstance(value, int):
            # Handle integer
            # Convert to binary string and process
            binary = bin(value)[2:]  # Remove '0b' prefix
            self.__init__(binary)
        else:
            raise TypeError(f"Unsupported type: {type(value)}")
    
    def __len__(self) -> int:
        """Return the number of bits in the array."""
        return len(self.bits)
    
    def __getitem__(self, index) -> ExistenceBit:
        """Get the bit at the specified index."""
        return self.bits[index]
    
    def __setitem__(self, index, value):
        """Set the bit at the specified index."""
        self.bits[index] = ExistenceBit(value)
    
    def __repr__(self) -> str:
        """Return a string representation of the bit array."""
        return "ExistenceBitArray([" + ", ".join(repr(bit) for bit in self.bits) + "])"
    
    def __str__(self) -> str:
        """Return a binary string representation."""
        return "".join(str(bit.to_traditional()) for bit in self.bits)
    
    def to_bytes(self) -> bytes:
        """Convert the bit array to bytes."""
        # Ensure the array has a multiple of 8 bits
        padding = (8 - len(self.bits) % 8) % 8
        padded_bits = self.bits + [ExistenceBit("!1") for _ in range(padding)]
        
        # Convert to bytes
        result = bytearray()
        for i in range(0, len(padded_bits), 8):
            byte = 0
            for j in range(8):
                if i + j < len(padded_bits):
                    byte = (byte << 1) | padded_bits[i + j].to_traditional()
            result.append(byte)
        
        return bytes(result)
    
    def to_int(self) -> int:
        """Convert the bit array to an integer."""
        binary_str = "".join(str(bit.to_traditional()) for bit in self.bits)
        return int(binary_str, 2) if binary_str else 0
    
    def to_traditional_binary(self) -> str:
        """Convert to traditional binary string (0s and 1s)."""
        return "".join(str(bit.to_traditional()) for bit in self.bits)
    
    def to_existence_notation(self) -> str:
        """Convert to existence notation string."""
        return "[" + ", ".join(bit.to_existence_notation() for bit in self.bits) + "]"
    
    def __xor__(self, other) -> 'ExistenceBitArray':
        """Implement XOR operation for bit arrays."""
        if isinstance(other, (bytes, str, int)):
            other = ExistenceBitArray(other)
        
        if not isinstance(other, ExistenceBitArray):
            return NotImplemented
        
        # Ensure arrays are the same length
        length = max(len(self), len(other))
        result = ExistenceBitArray(length=length)
        
        # Pad shorter array with !1
        self_padded = self.bits + [ExistenceBit("!1")] * (length - len(self))
        other_padded = other.bits + [ExistenceBit("!1")] * (length - len(other))
        
        # Perform XOR operation bit by bit
        for i in range(length):
            result[i] = self_padded[i] ^ other_padded[i]
        
        return result
    
    def __and__(self, other) -> 'ExistenceBitArray':
        """Implement AND operation for bit arrays."""
        if isinstance(other, (bytes, str, int)):
            other = ExistenceBitArray(other)
        
        if not isinstance(other, ExistenceBitArray):
            return NotImplemented
        
        # Ensure arrays are the same length
        length = max(len(self), len(other))
        result = ExistenceBitArray(length=length)
        
        # Pad shorter array with !1
        self_padded = self.bits + [ExistenceBit("!1")] * (length - len(self))
        other_padded = other.bits + [ExistenceBit("!1")] * (length - len(other))
        
        # Perform AND operation bit by bit
        for i in range(length):
            result[i] = self_padded[i] & other_padded[i]
        
        return result
    
    def __or__(self, other) -> 'ExistenceBitArray':
        """Implement OR operation for bit arrays."""
        if isinstance(other, (bytes, str, int)):
            other = ExistenceBitArray(other)
        
        if not isinstance(other, ExistenceBitArray):
            return NotImplemented
        
        # Ensure arrays are the same length
        length = max(len(self), len(other))
        result = ExistenceBitArray(length=length)
        
        # Pad shorter array with !1
        self_padded = self.bits + [ExistenceBit("!1")] * (length - len(self))
        other_padded = other.bits + [ExistenceBit("!1")] * (length - len(other))
        
        # Perform OR operation bit by bit
        for i in range(length):
            result[i] = self_padded[i] | other_padded[i]
        
        return result
    
    def __invert__(self) -> 'ExistenceBitArray':
        """Implement NOT operation for bit arrays."""
        result = ExistenceBitArray(length=len(self))
        
        # Negate each bit
        for i in range(len(self)):
            result[i] = ~self.bits[i]
        
        return result
    
    def calculate_void_factor(self) -> float:
        """
        Calculate the overall void factor of the bit array.
        
        Returns:
            A float between 0.0 and 1.0 representing the void factor.
        """
        if not self.bits:
            return 0.0
        
        total_void = sum(bit.get_void_factor() for bit in self.bits)
        return total_void / len(self.bits)
    
    def count_void_sequences(self) -> dict:
        """
        Count sequences of void states.
        
        Returns:
            A dictionary with the counts of different void sequences.
        """
        result = {"single": 0, "double": 0, "triple": 0, "quad": 0, "quint+": 0}
        
        # Find sequences of consecutive void states
        current_sequence = 0
        for bit in self.bits:
            if not bit.exists:
                current_sequence += 1
            else:
                # Record the sequence length
                if current_sequence == 1:
                    result["single"] += 1
                elif current_sequence == 2:
                    result["double"] += 1
                elif current_sequence == 3:
                    result["triple"] += 1
                elif current_sequence == 4:
                    result["quad"] += 1
                elif current_sequence > 4:
                    result["quint+"] += 1
                
                # Reset the sequence counter
                current_sequence = 0
        
        # Handle the last sequence if it ends with void states
        if current_sequence == 1:
            result["single"] += 1
        elif current_sequence == 2:
            result["double"] += 1
        elif current_sequence == 3:
            result["triple"] += 1
        elif current_sequence == 4:
            result["quad"] += 1
        elif current_sequence > 4:
            result["quint+"] += 1
        
        return result
    
    def find_deep_void_states(self, threshold=2) -> List[Tuple[int, int]]:
        """
        Find positions of deep void states (bits with high negation depth).
        
        Args:
            threshold: The minimum negation depth to consider a void state "deep".
        
        Returns:
            A list of tuples (index, depth) for deep void states.
        """
        deep_voids = []
        
        for i, bit in enumerate(self.bits):
            if not bit.exists and bit.negation_depth >= threshold:
                deep_voids.append((i, bit.negation_depth))
        
        return deep_voids


def demonstrate_existence_bit():
    """Simple demonstration of ExistenceBit behavior."""
    print("ExistenceBit Demonstration")
    print("-" * 40)
    
    # Create bits
    bit_1 = ExistenceBit(1)
    bit_0 = ExistenceBit(0)
    bit_not1 = ExistenceBit("!1")
    bit_not_not1 = ExistenceBit("!!1")
    
    print(f"bit_1 = {bit_1}")
    print(f"bit_0 = {bit_0}")
    print(f"bit_not1 = {bit_not1}")
    print(f"bit_not_not1 = {bit_not_not1}")
    
    # Show equivalence
    print("\nEquivalence:")
    print(f"bit_0 == bit_not1: {bit_0 == bit_not1}")
    print(f"bit_1 == bit_not_not1: {bit_1 == bit_not_not1}")
    
    # Demonstrate XOR operations
    print("\nXOR Operations:")
    print(f"1 ⊕ 1 = {bit_1 ^ bit_1}")
    print(f"1 ⊕ !1 = {bit_1 ^ bit_not1}")
    print(f"!1 ⊕ !1 = {bit_not1 ^ bit_not1}")
    
    # Demonstrate XOR non-reversibility
    a = ExistenceBit(1)
    b = ExistenceBit(0)
    c = a ^ b
    d = c ^ b
    
    print("\nXOR Reversibility Test:")
    print(f"a = {a}")
    print(f"b = {b}")
    print(f"c = a ⊕ b = {c}")
    print(f"d = c ⊕ b = {d}")
    print(f"a == d: {a == d}  (Should be True in traditional binary, but is {a == d} in existence semantics)")


def demonstrate_existence_bit_array():
    """Simple demonstration of ExistenceBitArray behavior."""
    print("\nExistenceBitArray Demonstration")
    print("-" * 40)
    
    # Create bit arrays
    array1 = ExistenceBitArray("10101010")
    array2 = ExistenceBitArray("11110000")
    
    print(f"array1 = {array1}")
    print(f"array2 = {array2}")
    
    # Demonstrate operations
    print("\nBit Array Operations:")
    print(f"array1 ⊕ array2 = {array1 ^ array2}")
    print(f"array1 & array2 = {array1 & array2}")
    print(f"array1 | array2 = {array1 | array2}")
    print(f"~array1 = {~array1}")
    
    # Demonstrate conversion methods
    print("\nConversion Methods:")
    print(f"array1.to_bytes() = {array1.to_bytes().hex()}")
    print(f"array1.to_int() = {array1.to_int()}")
    print(f"array1.to_existence_notation() = {array1.to_existence_notation()}")
    
    # Demonstrate void analysis
    print("\nVoid Analysis:")
    print(f"array1.calculate_void_factor() = {array1.calculate_void_factor():.4f}")
    print(f"array1.count_void_sequences() = {array1.count_void_sequences()}")
    print(f"array1.find_deep_void_states() = {array1.find_deep_void_states()}")


if __name__ == "__main__":
    demonstrate_existence_bit()
    demonstrate_existence_bit_array()
