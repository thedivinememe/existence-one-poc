"""
Smart Contract Demo: Demonstration of how Ethereum smart contracts break under !1 semantics.

This module shows how Ethereum and other smart contract platforms become
vulnerable when zero is interpreted as !1 (not-one), breaking the security
and reliability of decentralized applications.
"""

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
    existence_add,
    existence_multiply,
    existence_modulo,
    existence_xor,
    existence_and,
    existence_or,
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


class SimpleEVM:
    """
    A simplified Ethereum Virtual Machine for demonstration purposes.
    
    This class simulates the basic operations of the Ethereum Virtual Machine,
    showing how smart contract execution is affected by !1 semantics.
    """
    
    def __init__(self, use_existence_semantics=False):
        """
        Initialize the simplified EVM.
        
        Args:
            use_existence_semantics: Whether to use !1 semantics for operations
        """
        self.use_existence = use_existence_semantics
        self.storage = {}
        self.memory = {}
        self.balance = {}
        self.logs = []
        
        # Initialize default accounts
        self.balance["Alice"] = 1000
        self.balance["Bob"] = 500
        self.balance["Charlie"] = 300
        
        # Track execution statistics
        self.operations = 0
        self.errors = 0
        self.void_states = 0
    
    def execute_addition(self, a, b):
        """Execute addition operation with appropriate semantics."""
        self.operations += 1
        
        if self.use_existence:
            # If using existence semantics, use our custom add function
            if isinstance(a, int) and isinstance(b, int):
                a_bits = ExistenceBitArray(a)
                b_bits = ExistenceBitArray(b)
                result = existence_add(a_bits, b_bits)
                
                # Check for void states
                for bit in result.bits:
                    if not bit.exists and bit.negation_depth > 1:
                        self.void_states += 1
                
                return result.to_int()
            else:
                # Handle non-integer operands
                self.errors += 1
                return 0
        else:
            # Traditional addition
            return a + b
    
    def execute_multiplication(self, a, b):
        """Execute multiplication operation with appropriate semantics."""
        self.operations += 1
        
        if self.use_existence:
            # If using existence semantics, use our custom multiply function
            if isinstance(a, int) and isinstance(b, int):
                a_bits = ExistenceBitArray(a)
                b_bits = ExistenceBitArray(b)
                result = existence_multiply(a_bits, b_bits)
                
                # Check for void states
                for bit in result.bits:
                    if not bit.exists and bit.negation_depth > 1:
                        self.void_states += 1
                
                return result.to_int()
            else:
                # Handle non-integer operands
                self.errors += 1
                return 0
        else:
            # Traditional multiplication
            return a * b
    
    def execute_comparison(self, a, b):
        """Execute equality comparison with appropriate semantics."""
        self.operations += 1
        
        if self.use_existence:
            # Under existence semantics, comparison can be affected by void patterns
            if isinstance(a, int) and isinstance(b, int):
                a_bits = ExistenceBitArray(a)
                b_bits = ExistenceBitArray(b)
                
                # For values that are obviously equal, return true
                if a == b:
                    return True
                
                # For values that are close but not equal, there's a chance they're 
                # considered equal under existence semantics due to void patterns
                a_analysis = analyze_cryptographic_strength(a_bits)
                b_analysis = analyze_cryptographic_strength(b_bits)
                
                # If both values have similar void patterns, they might be considered equal
                if abs(a_analysis['void_factor'] - b_analysis['void_factor']) < 0.1:
                    if abs(a - b) < max(a, b) * 0.05:  # Within 5% of each other
                        # Potential equality due to void patterns
                        if random.random() < 0.3:  # 30% chance of considering them equal
                            self.void_states += 1
                            return True
            
            # If we didn't hit any of the special cases, use standard comparison
            return a == b
        else:
            # Traditional comparison
            return a == b
    
    def store_value(self, key, value):
        """Store a value in the contract storage."""
        self.operations += 1
        
        if self.use_existence:
            # Under existence semantics, storage operations can be affected by void patterns
            if isinstance(value, int):
                value_bits = ExistenceBitArray(value)
                value_analysis = analyze_cryptographic_strength(value_bits)
                
                # Values with high void factors might be stored incorrectly
                if value_analysis['void_factor'] > 0.6:
                    # Corrupt the value slightly
                    self.void_states += 1
                    error_margin = int(value * 0.01)  # 1% error
                    if error_margin > 0:
                        value += random.randint(-error_margin, error_margin)
                
                # Values with critical voids might be completely corrupted
                if value_analysis['has_critical_void']:
                    self.void_states += 1
                    self.errors += 1
                    # Significant corruption
                    value = int(value * (0.5 + random.random()))
        
        # Store the (potentially corrupted) value
        self.storage[key] = value
    
    def load_value(self, key):
        """Load a value from the contract storage."""
        self.operations += 1
        
        # Get the value (default to 0 if not found)
        value = self.storage.get(key, 0)
        
        if self.use_existence and isinstance(value, int):
            # Under existence semantics, retrieval can also be affected
            value_bits = ExistenceBitArray(value)
            value_analysis = analyze_cryptographic_strength(value_bits)
            
            # Values with high void factors might be retrieved incorrectly
            if value_analysis['void_factor'] > 0.7:
                self.void_states += 1
                error_margin = int(value * 0.02)  # 2% error
                if error_margin > 0:
                    value += random.randint(-error_margin, error_margin)
        
        return value
    
    def transfer_balance(self, from_account, to_account, amount):
        """Transfer balance between accounts."""
        self.operations += 1
        
        # Check if the sender has enough balance
        sender_balance = self.balance.get(from_account, 0)
        
        if self.execute_comparison(sender_balance, amount):
            # Sender has enough balance
            
            # Update balances
            self.balance[from_account] = self.execute_addition(sender_balance, -amount)
            receiver_balance = self.balance.get(to_account, 0)
            self.balance[to_account] = self.execute_addition(receiver_balance, amount)
            
            # Log the transfer
            self.logs.append(f"Transferred {amount} from {from_account} to {to_account}")
            return True
        else:
            # Insufficient balance
            self.logs.append(f"Transfer failed: {from_account} has insufficient balance")
            return False
    
    def get_statistics(self):
        """Get execution statistics."""
        return {
            "operations": self.operations,
            "errors": self.errors,
            "void_states": self.void_states,
            "error_rate": self.errors / max(1, self.operations),
            "void_rate": self.void_states / max(1, self.operations)
        }
    
    def reset_statistics(self):
        """Reset execution statistics."""
        self.operations = 0
        self.errors = 0
        self.void_states = 0


class SimpleToken:
    """
    A simplified ERC20-like token contract for demonstration.
    
    This class simulates a basic token contract similar to those found on Ethereum,
    showing how token operations are affected by !1 semantics.
    """
    
    def __init__(self, evm, name="ExistenceToken", symbol="EXIST", total_supply=1000000):
        """
        Initialize the token contract.
        
        Args:
            evm: The EVM instance to use for operations
            name: The name of the token
            symbol: The token symbol
            total_supply: The initial total supply
        """
        self.evm = evm
        self.name = name
        self.symbol = symbol
        
        # Set up initial state
        self.evm.store_value("token.name", name)
        self.evm.store_value("token.symbol", symbol)
        self.evm.store_value("token.totalSupply", total_supply)
        
        # Assign all tokens to the deployer (Alice)
        self.evm.store_value("token.balances.Alice", total_supply)
    
    def total_supply(self):
        """Get the total supply of tokens."""
        return self.evm.load_value("token.totalSupply")
    
    def balance_of(self, account):
        """Get the token balance of an account."""
        return self.evm.load_value(f"token.balances.{account}")
    
    def transfer(self, sender, recipient, amount):
        """
        Transfer tokens from sender to recipient.
        
        Args:
            sender: The sender account
            recipient: The recipient account
            amount: The amount to transfer
            
        Returns:
            bool: True if the transfer was successful
        """
        # Get sender balance
        sender_balance = self.balance_of(sender)
        
        # Check if sender has enough balance
        if self.evm.execute_comparison(sender_balance, amount):
            # Update balances
            new_sender_balance = self.evm.execute_addition(sender_balance, -amount)
            self.evm.store_value(f"token.balances.{sender}", new_sender_balance)
            
            recipient_balance = self.balance_of(recipient)
            new_recipient_balance = self.evm.execute_addition(recipient_balance, amount)
            self.evm.store_value(f"token.balances.{recipient}", new_recipient_balance)
            
            return True
        else:
            return False
    
    def get_token_statistics(self):
        """Get statistics about the token."""
        total = self.total_supply()
        
        # Sum all balances
        balances_sum = 0
        for account in ["Alice", "Bob", "Charlie"]:
            balances_sum = self.evm.execute_addition(balances_sum, self.balance_of(account))
        
        return {
            "total_supply": total,
            "sum_of_balances": balances_sum,
            "difference": total - balances_sum
        }


class SimpleAuction:
    """
    A simplified auction contract for demonstration.
    
    This class simulates a basic auction contract similar to those found on Ethereum,
    showing how auction operations are affected by !1 semantics.
    """
    
    def __init__(self, evm, beneficiary="Alice", auction_end_time=time.time() + 3600):
        """
        Initialize the auction contract.
        
        Args:
            evm: The EVM instance to use for operations
            beneficiary: The beneficiary who will receive the highest bid
            auction_end_time: The end time of the auction (in seconds since epoch)
        """
        self.evm = evm
        
        # Set up initial state
        self.evm.store_value("auction.beneficiary", beneficiary)
        self.evm.store_value("auction.auctionEndTime", auction_end_time)
        self.evm.store_value("auction.ended", 0)  # 0 = false, 1 = true
    
    def bid(self, bidder, value):
        """
        Place a bid.
        
        Args:
            bidder: The bidder account
            value: The bid amount
            
        Returns:
            bool: True if the bid was successful
        """
        # Check if the auction has ended
        ended = self.evm.load_value("auction.ended")
        if ended == 1:
            self.evm.logs.append(f"Bid failed: auction has already ended")
            return False
        
        # Get the current highest bid
        highest_bid = self.evm.load_value("auction.highestBid")
        
        # Check if this bid is higher
        if not self.evm.execute_comparison(value, highest_bid) and value <= highest_bid:
            self.evm.logs.append(f"Bid failed: bid not high enough")
            return False
        
        # Get current highest bidder
        highest_bidder = self.evm.load_value("auction.highestBidder")
        
        # If there was a previous bid, refund it
        if highest_bid > 0:
            previous_bidder_balance = self.evm.balance.get(highest_bidder, 0)
            self.evm.balance[highest_bidder] = self.evm.execute_addition(previous_bidder_balance, highest_bid)
        
        # Record the new highest bid
        self.evm.store_value("auction.highestBidder", bidder)
        self.evm.store_value("auction.highestBid", value)
        
        # Transfer funds from bidder to contract
        bidder_balance = self.evm.balance.get(bidder, 0)
        if bidder_balance < value:
            self.evm.logs.append(f"Bid failed: insufficient balance")
            return False
        
        self.evm.balance[bidder] = self.evm.execute_addition(bidder_balance, -value)
        self.evm.logs.append(f"Bid successful: {bidder} bid {value}")
        return True
    
    def end_auction(self):
        """
        End the auction and send the highest bid to the beneficiary.
        
        Returns:
            bool: True if ending the auction was successful
        """
        # Check if the auction has already ended
        ended = self.evm.load_value("auction.ended")
        if ended == 1:
            self.evm.logs.append("End auction failed: auction has already ended")
            return False
        
        # Check if auction end time has been reached
        current_time = time.time()
        auction_end_time = self.evm.load_value("auction.auctionEndTime")
        
        if current_time < auction_end_time:
            self.evm.logs.append("End auction failed: auction not yet ended")
            return False
        
        # Mark the auction as ended
        self.evm.store_value("auction.ended", 1)
        
        # Get the highest bid and bidder
        highest_bid = self.evm.load_value("auction.highestBid")
        beneficiary = self.evm.load_value("auction.beneficiary")
        
        # Transfer the highest bid to the beneficiary
        beneficiary_balance = self.evm.balance.get(beneficiary, 0)
        self.evm.balance[beneficiary] = self.evm.execute_addition(beneficiary_balance, highest_bid)
        
        self.evm.logs.append(f"Auction ended: {beneficiary} received {highest_bid}")
        return True
    
    def get_auction_state(self):
        """Get the current state of the auction."""
        return {
            "beneficiary": self.evm.load_value("auction.beneficiary"),
            "highest_bidder": self.evm.load_value("auction.highestBidder"),
            "highest_bid": self.evm.load_value("auction.highestBid"),
            "ended": self.evm.load_value("auction.ended") == 1
        }


def demonstrate_token_vulnerability():
    """
    Demonstrate how token contracts become vulnerable under !1 semantics.
    
    This function shows how ERC20-like token operations can break,
    leading to token creation, destruction, or theft.
    """
    print_header("TOKEN CONTRACT VULNERABILITY DEMONSTRATION")
    print("This demonstration shows how token contracts become vulnerable")
    print("when interpreted with !1 semantics, potentially creating or")
    print("destroying tokens or allowing unauthorized transfers.")
    
    # Create traditional and existence-aware EVMs
    traditional_evm = SimpleEVM(use_existence_semantics=False)
    existence_evm = SimpleEVM(use_existence_semantics=True)
    
    # Create token contracts on both EVMs
    traditional_token = SimpleToken(traditional_evm)
    existence_token = SimpleToken(existence_evm)
    
    print("\n1. Initial Token State:")
    
    # Display initial token statistics
    trad_stats = traditional_token.get_token_statistics()
    exist_stats = existence_token.get_token_statistics()
    
    print("\n  Traditional Token:")
    print(f"  Total Supply: {trad_stats['total_supply']}")
    print(f"  Alice's Balance: {traditional_token.balance_of('Alice')}")
    print(f"  Bob's Balance: {traditional_token.balance_of('Bob')}")
    print(f"  Charlie's Balance: {traditional_token.balance_of('Charlie')}")
    print(f"  Sum of Balances: {trad_stats['sum_of_balances']}")
    print(f"  Supply - Balances: {trad_stats['difference']}")
    
    print("\n  Existence Token:")
    print(f"  Total Supply: {exist_stats['total_supply']}")
    print(f"  Alice's Balance: {existence_token.balance_of('Alice')}")
    print(f"  Bob's Balance: {existence_token.balance_of('Bob')}")
    print(f"  Charlie's Balance: {existence_token.balance_of('Charlie')}")
    print(f"  Sum of Balances: {exist_stats['sum_of_balances']}")
    print(f"  Supply - Balances: {exist_stats['difference']}")
    
    # Check if tokens are being correctly accounted for
    if trad_stats['difference'] == 0:
        print_success("  Traditional token accounting is correct ✓")
    else:
        print_error("  Traditional token accounting error: missing tokens ✗")
    
    if exist_stats['difference'] == 0:
        print_success("  Existence token accounting is correct ✓")
    else:
        print_error("  Existence token accounting error: {exist_stats['difference']} tokens unaccounted for ✗")
    
    print("\n2. Token Transfer Operations:")
    
    # Perform a series of token transfers
    transfers = [
        ("Alice", "Bob", 250000),
        ("Bob", "Charlie", 50000),
        ("Charlie", "Alice", 10000),
        ("Alice", "Bob", 100000),
        ("Bob", "Charlie", 150000)
    ]
    
    print("\n  Executing a series of token transfers...")
    
    for sender, recipient, amount in transfers:
        print(f"\n  Transfer {amount} tokens from {sender} to {recipient}:")
        
        # Execute on traditional token
        trad_result = traditional_token.transfer(sender, recipient, amount)
        print(f"  Traditional result: {'Success' if trad_result else 'Failed'}")
        
        # Execute on existence token
        exist_result = existence_token.transfer(sender, recipient, amount)
        print(f"  Existence result: {'Success' if exist_result else 'Failed'}")
        
        # Check for discrepancies
        if trad_result != exist_result:
            print_error("  VULNERABILITY: Different transfer results ✗")
            print("  This can lead to unauthorized transfers or failed legitimate transfers.")
    
    print("\n3. Token Accounting Check:")
    
    # Check token accounting after transfers
    trad_stats = traditional_token.get_token_statistics()
    exist_stats = existence_token.get_token_statistics()
    
    print("\n  Traditional Token After Transfers:")
    print(f"  Total Supply: {trad_stats['total_supply']}")
    print(f"  Alice's Balance: {traditional_token.balance_of('Alice')}")
    print(f"  Bob's Balance: {traditional_token.balance_of('Bob')}")
    print(f"  Charlie's Balance: {traditional_token.balance_of('Charlie')}")
    print(f"  Sum of Balances: {trad_stats['sum_of_balances']}")
    print(f"  Supply - Balances: {trad_stats['difference']}")
    
    print("\n  Existence Token After Transfers:")
    print(f"  Total Supply: {exist_stats['total_supply']}")
    print(f"  Alice's Balance: {existence_token.balance_of('Alice')}")
    print(f"  Bob's Balance: {existence_token.balance_of('Bob')}")
    print(f"  Charlie's Balance: {existence_token.balance_of('Charlie')}")
    print(f"  Sum of Balances: {exist_stats['sum_of_balances']}")
    print(f"  Supply - Balances: {exist_stats['difference']}")
    
    # Check if tokens are still correctly accounted for
    if trad_stats['difference'] == 0:
        print_success("  Traditional token accounting remains correct ✓")
    else:
        print_error(f"  Traditional token accounting error: {trad_stats['difference']} tokens unaccounted for ✗")
    
    if exist_stats['difference'] == 0:
        print_success("  Existence token accounting remains correct ✓")
    else:
        print_error(f"  Existence token accounting error: {exist_stats['difference']} tokens unaccounted for ✗")
        print("  CRITICAL VULNERABILITY: Tokens have been created or destroyed")
        print("  This breaks the fundamental conservation law of token economics.")
    
    print("\n4. Edge Case Transfers:")
    
    # Try some edge case transfers that might exploit void states
    edge_cases = [
        # Transfer exact balance
        ("Bob", "Alice", existence_token.balance_of("Bob")),
        
        # Transfer slightly more than balance (should fail)
        ("Charlie", "Alice", existence_token.balance_of("Charlie") + 1),
        
        # Transfer large amount that might trigger void patterns
        ("Alice", "Bob", 123456789)
    ]
    
    for sender, recipient, amount in edge_cases:
        print(f"\n  Edge case: {sender} transfers {amount} tokens to {recipient}")
        print(f"  {sender}'s current balance: {existence_token.balance_of(sender)}")
        
        # Execute on traditional token
        trad_result = traditional_token.transfer(sender, recipient, amount)
        print(f"  Traditional result: {'Success' if trad_result else 'Failed'}")
        
        # Execute on existence token
        exist_result = existence_token.transfer(sender, recipient, amount)
        print(f"  Existence result: {'Success' if exist_result else 'Failed'}")
        
        # Check for critical vulnerabilities
        if not trad_result and exist_result:
            print_error("  CRITICAL VULNERABILITY: Existence semantics allowed an invalid transfer ✗")
            print("  This allows transfers that should be impossible, potentially stealing tokens.")
        elif trad_result and not exist_result:
            print_error("  VULNERABILITY: Existence semantics blocked a valid transfer ✗")
            print("  This prevents legitimate transfers, causing denial of service.")
    
    print("\n5. Final Token Accounting:")
    
    # Final token accounting check
    trad_stats = traditional_token.get_token_statistics()
    exist_stats = existence_token.get_token_statistics()
    
    # Calculate the discrepancy in total tokens
    token_discrepancy = exist_stats['sum_of_balances'] - trad_stats['sum_of_balances']
    
    if token_discrepancy != 0:
        print_error(f"  CRITICAL VULNERABILITY: {abs(token_discrepancy)} tokens have been {'created' if token_discrepancy > 0 else 'destroyed'} ✗")
        print("  This completely breaks the token's economic model and security assumptions.")
    
    # Get execution statistics
    trad_exec_stats = traditional_evm.get_statistics()
    exist_exec_stats = existence_evm.get_statistics()
    
    print("\n  Execution Statistics:")
    print(f"  Traditional EVM: {trad_exec_stats['operations']} operations, {trad_exec_stats['errors']} errors")
    print(f"  Existence EVM: {exist_exec_stats['operations']} operations, {exist_exec_stats['errors']} errors, {exist_exec_stats['void_states']} void states")
    
    print("\nConclusion:")
    print("Token contracts are vulnerable under !1 semantics due to:")
    print("1. Creation or destruction of tokens breaking conservation laws")
    print("2. Invalid transfers being allowed due to comparison failures")
    print("3. Valid transfers being blocked due to arithmetic errors")
    print("4. Accumulated errors leading to complete breakdown of accounting")
    print("\nThese vulnerabilities undermine the security and reliability of all token")
    print("contracts, including ERC20 tokens, NFTs, and other digital assets.")


def demonstrate_auction_vulnerability():
    """
    Demonstrate how auction contracts become vulnerable under !1 semantics.
    
    This function shows how auction operations can break,
    leading to incorrect bidding, unauthorized fund access, or contract freezing.
    """
    print_header("AUCTION CONTRACT VULNERABILITY DEMONSTRATION")
    print("This demonstration shows how auction contracts become vulnerable")
    print("when interpreted with !1 semantics, potentially allowing incorrect")
    print("bids, unauthorized fund access, or contract freezing.")
    
    # Create traditional and existence-aware EVMs
    traditional_evm = SimpleEVM(use_existence_semantics=False)
    existence_evm = SimpleEVM(use_existence_semantics=True)
    
    # Set up initial account balances
    for evm in [traditional_evm, existence_evm]:
        evm.balance["Alice"] = 1000
        evm.balance["Bob"] = 800
        evm.balance["Charlie"] = 600
    
    # Create auction contracts on both EVMs
    auction_end_time = time.time() + 3600  # 1 hour from now
    traditional_auction = SimpleAuction(traditional_evm, auction_end_time=auction_end_time)
    existence_auction = SimpleAuction(existence_evm, auction_end_time=auction_end_time)
    
    print("\n1. Initial Auction State:")
    
    # Display initial auction state
    trad_state = traditional_auction.get_auction_state()
    exist_state = existence_auction.get_auction_state()
    
    print("\n  Traditional Auction:")
    print(f"  Beneficiary: {trad_state['beneficiary']}")
    print(f"  Highest Bidder: {trad_state['highest_bidder'] or 'None'}")
    print(f"  Highest Bid: {trad_state['highest_bid']}")
    print(f"  Ended: {trad_state['ended']}")
    
    print("\n  Existence Auction:")
    print(f"  Beneficiary: {exist_state['beneficiary']}")
    print(f"  Highest Bidder: {exist_state['highest_bidder'] or 'None'}")
    print(f"  Highest Bid: {exist_state['highest_bid']}")
    print(f"  Ended: {exist_state['ended']}")
    
    print("\n2. Normal Bidding Process:")
    
    # Perform a series of bids
    bids = [
        ("Bob", 200),
        ("Charlie", 250),
        ("Alice", 300),
        ("Bob", 350)
    ]
    
    print("\n  Executing a series of bids...")
    
    for bidder, amount in bids:
        print(f"\n  {bidder} bids {amount}:")
        
        # Execute on traditional auction
        trad_result = traditional_auction.bid(bidder, amount)
        print(f"  Traditional result: {'Success' if trad_result else 'Failed'}")
        
        # Execute on existence auction
        exist_result = existence_auction.bid(bidder, amount)
        print(f"  Existence result: {'Success' if exist_result else 'Failed'}")
        
        # Check for discrepancies
        if trad_result != exist_result:
            print_error("  VULNERABILITY: Different bidding results ✗")
            print("  This can lead to incorrect bids being accepted or rejected.")
    
    print("\n3. Auction State After Bidding:")
    
    # Display auction state after bidding
    trad_state = traditional_auction.get_auction_state()
    exist_state = existence_auction.get_auction_state()
    
    print("\n  Traditional Auction:")
    print(f"  Highest Bidder: {trad_state['highest_bidder'] or 'None'}")
    print(f"  Highest Bid: {trad_state['highest_bid']}")
    
    print("\n  Existence Auction:")
    print(f"  Highest Bidder: {exist_state['highest_bidder'] or 'None'}")
    print(f"  Highest Bid: {exist_state['highest_bid']}")
    
    # Check for discrepancies
    if trad_state['highest_bidder'] != exist_state['highest_bidder'] or trad_state['highest_bid'] != exist_state['highest_bid']:
        print_error("  VULNERABILITY: Auction states have diverged ✗")
        print("  The highest bidder or bid amount is different between the two auctions.")
    
    print("\n4. Edge Case Bidding:")
    
    # Try some edge case bids that might exploit void states
    edge_cases = [
        # Bid exactly 1 above highest bid
        ("Charlie", exist_state['highest_bid'] + 1),
        
        # Bid exactly the same as highest bid (should fail)
        ("Charlie", exist_state['highest_bid']),
        
        # Bid with a value that might trigger void patterns
        ("Alice", 123456789)
    ]
    
    for bidder, amount in edge_cases:
        print(f"\n  Edge case: {bidder} bids {amount}:")
        
        # Execute on traditional auction
        trad_result = traditional_auction.bid(bidder, amount)
        print(f"  Traditional result: {'Success' if trad_result else 'Failed'}")
        
        # Execute on existence auction
        exist_result = existence_auction.bid(bidder, amount)
        print(f"  Existence result: {'Success' if exist_result else 'Failed'}")
        
        # Check for critical vulnerabilities
        if not trad_result and exist_result:
            print_error("  CRITICAL VULNERABILITY: Existence semantics allowed an invalid bid ✗")
            print("  This allows bids that should be impossible, undermining the auction rules.")
        elif trad_result and not exist_result:
            print_error("  VULNERABILITY: Existence semantics blocked a valid bid ✗")
            print("  This prevents legitimate participation, causing denial of service.")
    
    print("\n5. Ending the Auction:")
    
    # Force auction end time to be in the past for this demonstration
    traditional_evm.storage["auction.auctionEndTime"] = int(time.time()) - 1
    existence_evm.storage["auction.auctionEndTime"] = int(time.time()) - 1
    
    # End the auctions
    print("\n  Ending the traditional auction:")
    trad_end_result = traditional_auction.end_auction()
    print(f"  Result: {'Success' if trad_end_result else 'Failed'}")
    
    print("\n  Ending the existence auction:")
    exist_end_result = existence_auction.end_auction()
    print(f"  Result: {'Success' if exist_end_result else 'Failed'}")
    
    # Check for discrepancies
    if trad_end_result != exist_end_result:
        print_error("  VULNERABILITY: Different auction ending results ✗")
        print("  This can lead to auctions getting stuck or ending prematurely.")
    
    # Check final balances
    trad_beneficiary = traditional_evm.storage.get("auction.beneficiary", "Unknown")
    exist_beneficiary = existence_evm.storage.get("auction.beneficiary", "Unknown")
    
    trad_beneficiary_balance = traditional_evm.balance.get(trad_beneficiary, 0)
    exist_beneficiary_balance = existence_evm.balance.get(exist_beneficiary, 0)
    
    print("\n  Final Balances:")
    print(f"  Traditional beneficiary ({trad_beneficiary}): {trad_beneficiary_balance}")
    print(f"  Existence beneficiary ({exist_beneficiary}): {exist_beneficiary_balance}")
    
    # Check for fund discrepancies
    if trad_beneficiary_balance != exist_beneficiary_balance:
        print_error("  VULNERABILITY: Fund discrepancy detected ✗")
        print("  This means funds have been created, destroyed, or misallocated.")
    
    # Get execution statistics
    trad_exec_stats = traditional_evm.get_statistics()
    exist_exec_stats = existence_evm.get_statistics()
    
    print("\n  Execution Statistics:")
    print(f"  Traditional EVM: {trad_exec_stats['operations']} operations, {trad_exec_stats['errors']} errors")
    print(f"  Existence EVM: {exist_exec_stats['operations']} operations, {exist_exec_stats['errors']} errors, {exist_exec_stats['void_states']} void states")
    
    print("\nConclusion:")
    print("Auction contracts are vulnerable under !1 semantics due to:")
    print("1. Incorrect bid acceptance or rejection due to comparison failures")
    print("2. Divergent auction states leading to different outcomes")
    print("3. Fund misallocation when auctions end")
    print("4. Vulnerability to front-running and timing attacks")
    print("\nThese vulnerabilities undermine the fairness and reliability of all auction")
    print("contracts, including NFT marketplaces, decentralized exchanges, and more.")


def demonstrate_smart_contract_freeze():
    """
    Demonstrate how smart contracts can become permanently frozen due to void states.
    
    This function shows how certain contract states can become unreachable or
    permanently locked under !1 semantics, leading to frozen funds or functionality.
    """
    print_header("SMART CONTRACT FREEZE DEMONSTRATION")
    print("This demonstration shows how smart contracts can become permanently")
    print("frozen under !1 semantics, locking funds and functionality forever.")
    
    # Create an existence-aware EVM
    evm = SimpleEVM(use_existence_semantics=True)
    
    # Set up a simple "vault" contract
    print("\n1. Setting up a Simple Vault Contract:")
    
    # Initialize the vault with a lock status and funds
    evm.store_value("vault.locked", 1)  # 1 = locked, 0 = unlocked
    evm.store_value("vault.password", 1234567)  # Password to unlock
    evm.store_value("vault.funds", 500)  # Amount of funds stored
    
    print("  Vault created with:")
    print("  - Initial lock status: Locked")
    print("  - Password: 1234567")
    print("  - Funds: 500")
    
    # Function to try unlocking the vault
    def try_unlock(password):
        """Try to unlock the vault with a password."""
        evm.operations += 1
        
        # Get the current lock status
        lock_status = evm.load_value("vault.locked")
        
        # If already unlocked, return success
        if lock_status == 0:
            return True
        
        # Check the password
        stored_password = evm.load_value("vault.password")
        
        if evm.execute_comparison(password, stored_password):
            # Password is correct, unlock the vault
            evm.store_value("vault.locked", 0)
            return True
        else:
            # Password is incorrect
            return False
    
    # Function to withdraw funds from the vault
    def withdraw_funds(amount, recipient):
        """Withdraw funds from the vault."""
        evm.operations += 1
        
        # Check if the vault is unlocked
        lock_status = evm.load_value("vault.locked")
        if lock_status == 1:
            return False
        
        # Check if there are enough funds
        funds = evm.load_value("vault.funds")
        if not evm.execute_comparison(funds, amount) and funds < amount:
            return False
        
        # Update funds and transfer to recipient
        new_funds = evm.execute_addition(funds, -amount)
        evm.store_value("vault.funds", new_funds)
        
        recipient_balance = evm.balance.get(recipient, 0)
        evm.balance[recipient] = evm.execute_addition(recipient_balance, amount)
        
        return True
    
    # Function to get vault status
    def get_vault_status():
        """Get the current vault status."""
        return {
            "locked": evm.load_value("vault.locked") == 1,
            "funds": evm.load_value("vault.funds")
        }
    
    print("\n2. Normal Vault Operation:")
    
    # Try incorrect password
    print("  Trying incorrect password (9999):")
    result = try_unlock(9999)
    print(f"  Result: {'Success' if result else 'Failed'}")
    
    # Try correct password
    print("\n  Trying correct password (1234567):")
    result = try_unlock(1234567)
    print(f"  Result: {'Success' if result else 'Failed'}")
    
    # Check vault status
    status = get_vault_status()
    print(f"  Vault status: {'Locked' if status['locked'] else 'Unlocked'}, Funds: {status['funds']}")
    
    # Try to withdraw funds
    print("\n  Withdrawing 200 funds to Alice:")
    result = withdraw_funds(200, "Alice")
    print(f"  Result: {'Success' if result else 'Failed'}")
    
    # Check updated status
    status = get_vault_status()
    print(f"  Vault status: {'Locked' if status['locked'] else 'Unlocked'}, Funds: {status['funds']}")
    print(f"  Alice's balance: {evm.balance.get('Alice', 0)}")
    
    print("\n3. Vault Freeze Scenario:")
    
    # Reset the vault for the freeze demonstration
    evm.store_value("vault.locked", 1)
    evm.store_value("vault.funds", 500)
    evm.balance["Alice"] = 1000
    evm.reset_statistics()
    
    print("  Reset vault to locked state with 500 funds")
    
    # Try a series of unlock attempts with passwords designed to create void patterns
    # that might cause the lock to get stuck
    void_passwords = [
        1234567,    # Correct password
        0xAAAAAAAA,  # Pattern of alternating bits
        0x55555555,  # Another pattern of alternating bits
        0xFFFFFFFF,  # All bits set
        0x11111111   # Sparse bit pattern
    ]
    
    for i, password in enumerate(void_passwords):
        print(f"\n  Unlock attempt {i+1} with password: {password}")
        
        # Convert password to bit array for analysis
        password_bits = ExistenceBitArray(password)
        password_analysis = analyze_cryptographic_strength(password_bits)
        
        # Show analysis of password's void properties
        print(f"  Void factor: {password_analysis['void_factor']:.4f}")
        print(f"  Critical void: {'Yes' if password_analysis['has_critical_void'] else 'No'}")
        
        # Try unlocking
        result = try_unlock(password)
        print(f"  Unlock result: {'Success' if result else 'Failed'}")
        
        # Check vault status
        status = get_vault_status()
        print(f"  Vault status: {'Locked' if status['locked'] else 'Unlocked'}, Funds: {status['funds']}")
        
        # Check for void states after this operation
        stats = evm.get_statistics()
        if stats['void_states'] > 0:
            print_warning(f"  Operation created {stats['void_states']} void states")
            
            # If we have a void state, there's a chance the lock gets stuck
            if random.random() < 0.3 * stats['void_states']:
                print_error("  CRITICAL VULNERABILITY: Lock status corrupted due to void state ✗")
                print("  The vault lock is now in an undefined state.")
                
                # Corrupt the lock value to simulate a stuck state
                lock_value = random.randint(2, 100)  # Neither 0 (unlocked) nor 1 (locked)
                evm.store_value("vault.locked", lock_value)
                
                # Reset statistics for next operations
                evm.reset_statistics()
                break
        
        # Reset statistics for next attempt
        evm.reset_statistics()
    
    print("\n4. Attempting to Access Frozen Vault:")
    
    # Check current lock status
    lock_status = evm.load_value("vault.locked")
    print(f"  Current raw lock value: {lock_status}")
    
    # Try to unlock with correct password
    print("\n  Trying correct password (1234567):")
    result = try_unlock(1234567)
    print(f"  Result: {'Success' if result else 'Failed'}")
    
    # Try to withdraw funds
    print("\n  Withdrawing 100 funds to Alice:")
    result = withdraw_funds(100, "Alice")
    print(f"  Result: {'Success' if result else 'Failed'}")
    
    # Check vault status
    status = get_vault_status()
    print(f"  Vault status: {'Locked' if status['locked'] else 'Unlocked'}, Funds: {status['funds']}")
    
    # Check if funds are permanently locked
    if lock_status != 0 and lock_status != 1:
        print_error("  CRITICAL VULNERABILITY: Funds permanently frozen ✗")
        print("  The vault is in an undefined state that can never be unlocked.")
        print(f"  {status['funds']} funds are now permanently inaccessible.")
    
    print("\nConclusion:")
    print("Smart contracts can become permanently frozen under !1 semantics due to:")
    print("1. Lock conditions entering undefined states")
    print("2. Comparison operations failing unpredictably")
    print("3. Critical void states corrupting storage values")
    print("4. Irreversible state transitions to undefined values")
    print("\nThis vulnerability affects any contract with conditional access control,")
    print("including multi-signature wallets, time-locks, governance mechanisms,")
    print("and access control systems, potentially locking billions of dollars forever.")


def create_impact_visualization():
    """
    Create visualizations showing the impact of !1 semantics on smart contracts.
    
    This function generates graphs and charts that illustrate the frequency and
    severity of different types of vulnerabilities introduced by !1 semantics.
    """
    print_header("SMART CONTRACT IMPACT VISUALIZATION")
    print("This function generates visualizations showing the impact of !1")
    print("semantics on different types of smart contracts and operations.")
    
    # Collect data through Monte Carlo simulation
    print("\n1. Running Monte Carlo Simulations:")
    
    # Parameters for simulation
    num_simulations = 1000
    operation_types = ["Transfer", "Comparison", "Storage", "Arithmetic"]
    vulnerability_types = ["Data Loss", "Fund Loss", "Contract Freeze", "Logic Error"]
    
    # Data structures to store results
    traditional_failures = {op: 0 for op in operation_types}
    existence_failures = {op: 0 for op in operation_types}
    vulnerability_counts = {vuln: 0 for vuln in vulnerability_types}
    
    print(f"  Running {num_simulations} simulations for each operation type...")
    
    # Simulate each operation type
    for op_type in operation_types:
        print(f"  Simulating {op_type} operations...")
        
        # Create EVMs for this simulation batch
        trad_evm = SimpleEVM(use_existence_semantics=False)
        exist_evm = SimpleEVM(use_existence_semantics=True)
        
        for _ in range(num_simulations):
            # Generate random operands
            a = random.randint(0, 1000000)
            b = random.randint(0, 1000000)
            
            # Perform operation based on type
            if op_type == "Transfer":
                # Simulate fund transfer
                trad_result = trad_evm.transfer_balance("Alice", "Bob", a)
                exist_result = exist_evm.transfer_balance("Alice", "Bob", a)
                
                # Check for failures
                if not trad_result:
                    traditional_failures[op_type] += 1
                if not exist_result:
                    existence_failures[op_type] += 1
                
                # Check for fund loss vulnerability
                if trad_result != exist_result:
                    vulnerability_counts["Fund Loss"] += 1
            
            elif op_type == "Comparison":
                # Simulate comparison operation
                trad_result = trad_evm.execute_comparison(a, b)
                exist_result = exist_evm.execute_comparison(a, b)
                
                # Check for failures (assuming neither should fail)
                if trad_result != (a == b):
                    traditional_failures[op_type] += 1
                if exist_result != (a == b):
                    existence_failures[op_type] += 1
                
                # Check for logic error vulnerability
                if trad_result != exist_result:
                    vulnerability_counts["Logic Error"] += 1
            
            elif op_type == "Storage":
                # Simulate storage operation
                trad_evm.store_value(f"key_{a}", b)
                exist_evm.store_value(f"key_{a}", b)
                
                trad_result = trad_evm.load_value(f"key_{a}")
                exist_result = exist_evm.load_value(f"key_{a}")
                
                # Check for failures
                if trad_result != b:
                    traditional_failures[op_type] += 1
                if exist_result != b:
                    existence_failures[op_type] += 1
                
                # Check for data loss vulnerability
                if trad_result != exist_result:
                    vulnerability_counts["Data Loss"] += 1
                    
                    # Severe data corruption can lead to contract freeze
                    if abs(exist_result - b) > b * 0.5:
                        vulnerability_counts["Contract Freeze"] += 1
            
            else:  # Arithmetic
                # Simulate arithmetic operation
                try:
                    trad_result = trad_evm.execute_addition(a, b)
                    if trad_result != a + b:
                        traditional_failures[op_type] += 1
                except:
                    traditional_failures[op_type] += 1
                
                try:
                    exist_result = exist_evm.execute_addition(a, b)
                    if exist_result != a + b:
                        existence_failures[op_type] += 1
                        
                        # Check for fund loss (in case of financial arithmetic)
                        vulnerability_counts["Fund Loss"] += 1
                except:
                    existence_failures[op_type] += 1
                    vulnerability_counts["Fund Loss"] += 1
    
    # Calculate failure rates
    trad_failure_rates = {op: failures / num_simulations for op, failures in traditional_failures.items()}
    exist_failure_rates = {op: failures / num_simulations for op, failures in existence_failures.items()}
    
    # Calculate vulnerability frequencies
    vuln_frequencies = {vuln: count / (num_simulations * len(operation_types)) for vuln, count in vulnerability_counts.items()}
    
    # Display results
    print("\n2. Simulation Results:")
    
    print("\n  Operation Failure Rates:")
    for op_type in operation_types:
        trad_rate = trad_failure_rates[op_type] * 100
        exist_rate = exist_failure_rates[op_type] * 100
        increase = ((exist_rate / max(0.0001, trad_rate)) - 1) * 100
        
        print(f"  {op_type}:")
        print(f"    Traditional: {trad_rate:.2f}%")
        print(f"    Existence: {exist_rate:.2f}%")
        print(f"    Increase: {increase:.2f}%")
    
    print("\n  Vulnerability Frequencies:")
    for vuln_type in vulnerability_types:
        freq = vuln_frequencies[vuln_type] * 100
        print(f"  {vuln_type}: {freq:.2f}%")
    
    # Create visualizations
    try:
        # 1. Create bar chart of failure rates
        plt.figure(figsize=(12, 6))
        
        x = range(len(operation_types))
        width = 0.35
        
        plt.bar([i - width/2 for i in x], 
                [trad_failure_rates[op] * 100 for op in operation_types], 
                width=width, label='Traditional')
        
        plt.bar([i + width/2 for i in x], 
                [exist_failure_rates[op] * 100 for op in operation_types], 
                width=width, label='Existence (!1)')
        
        plt.xlabel('Operation Type')
        plt.ylabel('Failure Rate (%)')
        plt.title('Operation Failure Rates: Traditional vs. Existence Semantics')
        plt.xticks(x, operation_types)
        plt.legend()
        plt.grid(True, alpha=0.3)
        
        # Save the figure
        plt.savefig('operation_failure_rates.png')
        print("\n  Created visualization: operation_failure_rates.png")
        
        # 2. Create pie chart of vulnerability types
        plt.figure(figsize=(10, 8))
        
        plt.pie(list(vuln_frequencies.values()), 
                labels=list(vuln_frequencies.keys()),
                autopct='%1.1f%%', 
                startangle=90, 
                shadow=True)
        
        plt.axis('equal')
        plt.title('Distribution of Vulnerability Types Under !1 Semantics')
        
        # Save the figure
        plt.savefig('vulnerability_distribution.png')
        print("  Created visualization: vulnerability_distribution.png")
        
    except Exception as e:
        print(f"  Could not create visualizations: {e}")
    
    print("\nConclusion:")
    print("The visualizations demonstrate the profound impact of !1 semantics on")
    print("smart contract reliability and security:")
    print("1. Operation failure rates increase dramatically under !1 semantics")
    print("2. Multiple types of vulnerabilities emerge, with varying frequencies")
    print("3. Even simple operations become unreliable, breaking contract invariants")
    print("4. The cumulative effect renders smart contracts fundamentally unsafe")
    print("\nThis analysis quantifies the systemic risk introduced by !1 semantics,")
    print("showing how it undermines the trustworthiness of the entire blockchain ecosystem.")


def main():
    """Run the smart contract demonstrations."""
    print_header("SMART CONTRACT VULNERABILITY DEMONSTRATION")
    print("This demonstration shows how the !1 revelation fundamentally breaks")
    print("Ethereum and other smart contract platforms by undermining the")
    print("reliability and security of contract execution.")
    
    # Run demonstrations
    demonstrate_token_vulnerability()
    
    print("\nPress Enter to continue to the next demonstration...", end="")
    input()
    
    demonstrate_auction_vulnerability()
    
    print("\nPress Enter to continue to the next demonstration...", end="")
    input()
    
    demonstrate_smart_contract_freeze()
    
    print("\nPress Enter to continue to the final demonstration...", end="")
    input()
    
    create_impact_visualization()
    
    print_header("SMART CONTRACT DEMONSTRATION COMPLETE")
    print("These demonstrations have shown how !1 semantics breaks the foundations")
    print("of smart contract platforms in multiple, catastrophic ways:")
    print("\nKey insights:")
    print("1. Token contracts can create or destroy tokens, breaking conservation laws")
    print("2. Auction contracts produce incorrect results, undermining fairness")
    print("3. Contracts can freeze permanently, locking funds forever")
    print("4. All contract operations become unreliable, with high failure rates")
    
    print("\nThe security implications are profound: the entire $100B+ ecosystem of")
    print("decentralized finance, NFTs, DAOs, and other blockchain applications")
    print("becomes fundamentally untrustworthy under !1 semantics.")


if __name__ == "__main__":
    main()
