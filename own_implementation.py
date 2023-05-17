from Cryptodome.Hash import SHA256
from Cryptodome.PublicKey import RSA
from Cryptodome.Signature import pss
from Cryptodome.Hash import SHA256
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import binascii
import datetime as datetime

# Glbal variable for mining difficulty
DIFFICULTY = 2

class Block:
    def __init__(self, transactions = None, previous_block = None, nonce = "", previous_hash = "", timestamp = datetime.datetime.now()) -> None:
        self.transactions: list = transactions
        self.previous_block = previous_block
        self.nonce = nonce
        self.previous_hash = previous_hash
        self.timestamp = timestamp
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        block_data = str(self.transactions) + str(self.previous_block) + str(self.nonce) + str(self.previous_hash) + str(self.timestamp)
        return SHA256.new(block_data.encode('utf-8')).hexdigest()

class Transaction:
    def __init__(self, sender, recipient, amount, timestamp) -> None:
        self.sender = sender
        self.recipient = recipient
        self.amount = amount
        self.timestamp = timestamp
        self.signature = None

    def calculate_hash(self):
        transaction_data = str(self.sender) + str(self.recipient) + str(self.amount) + str(self.timestamp)
        return SHA256.new(transaction_data.encode('utf-8')).hexdigest()
    
    def sign_transaction(self, private_key):
        """
        Sign transaction with private key of the sender
        """
        # Deserialize the private key
        private_key_obj = serialization.load_pem_private_key(
            private_key,
            password=None,
            backend=default_backend()
        )
        
        transaction_data = str(self.sender) + str(self.recipient) + str(self.amount) + str(self.timestamp)
        transaction_data = transaction_data.encode('utf-8')

        self.signature = private_key_obj.sign(
            transaction_data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

# Utility function for veryifying transactions
def is_valid_signature(transaction : Transaction):
    message = RSA.import_key(transaction.sender).export_key(format='PEM').decode('utf-8') + str(transaction.recipient) + str(transaction.amount)
    message_hash = SHA256.new(message.encode('utf-8'))

    # Load the public key from PEM format
    public_key = RSA.import_key(transaction.sender)

    # Create a new signer with the public key
    signer = pss.new(public_key)
    try:
        # Try to verify the signature
        signer.verify(message_hash, binascii.unhexlify(transaction.signature))
        return True
    except (ValueError, TypeError):
        return False

class Blockchain:
    def __init__(self):
        self.chain = []  # This will store all the blocks
        self.pending_transactions = []  # Transactions that are not yet included in a block

    def create_genesis_block(self):
        # Create the first block of the chain, called the Genesis Block.
        # It doesn't have a previous hash reference.
        genesis_block = Block(transactions=[], previous_hash='')
        self.chain.append(genesis_block)

    def add_block(self, block : Block):
        # Add a new block to the chain. 
        # Before adding, we need to update the block's previous_hash to the hash of the last block in the chain
        # and we need to validate the block
        if len(self.chain) > 0:
            block.previous_hash = self.calculate_hash(self.chain[-1])
        self.validate_block(block)
        self.chain.append(block)

    def calculate_hash(self, block : Block):
        # Calculate the SHA256 hash of a block
        block_data = str(block.transactions) + str(block.previous_hash) + str(block.nonce)
        return SHA256.new(block_data.encode('utf-8')).hexdigest()


    def validate_block(self, block : Block):
        # Validate the block's transactions and verify the block's hash
        for transaction in block.transactions:
            self.validate_transaction(transaction)

        if block.hash != self.calculate_hash(block):
            raise Exception("Block hash is incorrect")

    def validate_transaction(self, transaction):
        # Validate a transaction.
        # In this case, check if the signature is valid.
        if not is_valid_signature(transaction):
            raise Exception("Transaction signature is invalid")

    def create_new_block(self, miner_wallet):
        # Create a new block with all pending transactions and add it to the blockchain
        new_block = Block(
            transactions=self.pending_transactions,
            previous_block=self.chain[-1],
            nonce=0,  # The nonce will be updated in the mining process
            previous_hash=self.calculate_hash(self.chain[-1]),  # Hash of the previous block
            timestamp=datetime.datetime.now()
        )
        self.add_block(new_block)
        # Clear out the pending transactions
        self.pending_transactions = []
        # Reward the miner by adding a new transaction granting them some coins
        self.pending_transactions.append(Transaction(sender="Network", recipient=miner_wallet.get_public_key(), amount=1, timestamp=datetime.datetime.now()))

    def add_transaction_to_pending(self, transaction):
        # Add a new transaction to the list of pending transactions
        self.pending_transactions.append(transaction)

# Utility function for generating key pairs
def generate_key_pair():
    # Generate a new private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,  # Commonly used public exponent
        key_size=2048,  # Size of the key. 2048 or higher is recommended.
        backend=default_backend()  # Use the default backend
    )
    # Generate the corresponding public key
    public_key = private_key.public_key()
    
    # Serializing keys to be used in transactions
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_pem, public_pem

class Wallet:
    def __init__(self, blockchain : Blockchain, network):
        # Generate a new public-private key pair for this wallet
        self.private_key, self.public_key = generate_key_pair()
        self.blockchain = blockchain

    def calculate_balance(self):
        # Calculate and return the current balance of this wallet
        balance = 0
        for block in self.blockchain.chain:
            for transaction in block.transactions:
                if transaction.recipient == self.public_key:
                    balance += transaction.amount
                if transaction.sender == self.public_key:
                    balance -= transaction.amount
        return balance

    def create_transaction(self, recipient_public_key, amount):
        # (code for checking the wallet balance remains the same)
        # Create a new transaction and sign it
        transaction = Transaction(self.public_key, recipient_public_key, amount, timestamp=datetime.datetime.now())
        transaction.sign_transaction(self.private_key)
        return transaction

    def get_public_key(self):
        # Return the public key of this wallet
        return self.public_key


class Node: # also known as "miner"
    def __init__(self, blockchain: Blockchain, network, wallet: Wallet) -> None:
        self.blockchain: Blockchain = blockchain
        self.network = network
        self.wallet = wallet

    def mine_block(self):
        # Step 1: Check if there are pending transactions
        if not self.blockchain.pending_transactions:
            print("No transactions to mine")
            return

        # Step 2: Create a new block with the current pending transactions
        new_block = Block(
            transactions=self.blockchain.pending_transactions, 
            previous_block=self.blockchain.chain[-1],
            nonce=0,  # The nonce will be updated in the mining process
            previous_hash=self.blockchain.calculate_hash(self.blockchain.chain[-1])  # Hash of the previous block
        )

        # Step 3: Find a nonce that, when hashed with the rest of the block, 
        # results in a hash that satisfies the proof-of-work condition.
        # This condition could be that the hash starts with a certain number of zeros.
        # This is a simple and adjustable condition, but it requires a lot of computation on average.
        target = '0' * DIFFICULTY  # Define the target hash for this block. 
        # "difficulty" is a parameter that determines how much computation is needed to mine a block.
        
        while True:
            new_block_hash = self.blockchain.calculate_hash(new_block)
            if new_block_hash[:DIFFICULTY] == target:
                print(f"Block mined with nonce: {new_block.nonce}")
                break
            else:
                new_block.nonce += 1

        # Step 4: Add the new block to the blockchain and clear out the pending transactions
        self.blockchain.add_block(new_block)
        self.blockchain.pending_transactions = []

        # Step 5: Broadcast the new block to the network (omitted in this pseudocode)
        self.broadcast(new_block)

        return new_block

    def broadcast(self, block):
        self.network.broadcast(block)

    def receive_block(self, block):
        self.blockchain.add_block(block)

    def receive_transaction(self, transaction):
        self.blockchain.add_transaction_to_pending(transaction)
    
class Network:
    def __init__(self, nodes = []) -> None:
        self.nodes : list[Node] = nodes
        self.transaction_pool = []

    def add_node(self, node):
        self.nodes.append(node)

    def add_unconfirmed_transaction(self, transaction):
        self.transaction_pool.append(transaction)

    def broadcast(self, block : Block):
        # Send the block to all nodes in the network
        for node in self.nodes:
            node.receive_block(block)

    def broadcast_transaction(self, transaction : Transaction):
        for node in self.nodes:
            node.receive_transaction(transaction)

def main():
    # Create a network
    network = Network()

    # Create a blockchain
    blockchain = Blockchain()

    # Add the genesis block
    blockchain.create_genesis_block()

    # Create a wallet for Alice and Bob
    alice_wallet = Wallet(blockchain, network)
    bob_wallet = Wallet(blockchain, network)

    # Create nodes for Alice and Bob
    alice_node = Node(blockchain, network, alice_wallet)
    bob_node = Node(blockchain, network, bob_wallet)

    # Add Alice and Bob nodes to the network
    network.add_node(alice_node)
    network.add_node(bob_node)

    # Alice sends 10 coins to Bob
    transaction = alice_wallet.create_transaction(bob_wallet.get_public_key(), 10)
    alice_node.receive_transaction(transaction)

    # Alice mines the block
    mined_block = alice_node.mine_block()

    # Check balances
    print("Alice's balance: ", alice_wallet.calculate_balance())
    print("Bob's balance: ", bob_wallet.calculate_balance())

    # Bob sends 5 coins back to Alice
    transaction = bob_wallet.create_transaction(alice_wallet.get_public_key(), 5)
    bob_node.receive_transaction(transaction)

    # Bob mines the block
    mined_block = bob_node.mine_block()

    # Check balances again
    print("Alice's balance: ", alice_wallet.calculate_balance())
    print("Bob's balance: ", bob_wallet.calculate_balance())

if __name__ == "__main__":
    main()
