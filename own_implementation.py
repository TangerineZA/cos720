class Block:
    def __init__(self, transactions, previous_block, nonce) -> None:
        self.transactions : list = transactions
        self.previous_block = previous_block
        self.nonce = nonce

class Transaction:
    def __init__(self, sender, recipient, amount, timestamp) -> None:
        self.sender = sender
        self.recipient = recipient
        self.amount = amount
        self.timestamp = timestamp
        self.signature = None

    def generate_signature(self):
        pass

class Blockchain:
    def __init__(self, blocks=[], difficulty=1) -> None:
        self.blocks = blocks
        self.difficult = difficulty

    def add_block(self):
        pass

    def validate_chain(self):
        pass

class Wallet:
    def __init__(self, public_key, private_key) -> None:
        self.public_key = public_key
        self.private_ley = private_key

    def create_transaction(self, amount, recipient):
        pass

    def sign_transaction(self):
        pass

class Node: # also known as "miner"
    def __init__(self, blockchain) -> None:
        self.blockchain = blockchain

    def mine_block(self):
        pass

    def validate_transaction(self):
        pass

    def broadcast(self):
        pass
    
class Network:
    def __init__(self, nodes = []) -> None:
        self.nodes = nodes
        self.transaction_pool = []

    def add_node(self, node):
        self.nodes.append(node)

    def add_unconfirmed_transaction(self, transaction):
        self.transaction_pool.append(transaction)

    def broadcast(self):
        pass