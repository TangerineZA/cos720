
import hashlib
import time

# global variable for difficulty
DIFFICULTY = 4

class Block:

    def __init__(self, index, proof_no, prev_hash, data, timestamp=None):
        self.index = index
        self.proof_no = proof_no
        self.prev_hash = prev_hash
        self.data = data
        self.timestamp = timestamp or time.time()

    @property
    def calculate_hash(self):
        block_of_string = "{}{}{}{}{}".format(self.index, self.proof_no,
                                              self.prev_hash, self.data,
                                              self.timestamp)

        return hashlib.sha256(block_of_string.encode()).hexdigest()

    def __repr__(self):
        return "{} - {} - {} - {} - {}".format(self.index, self.proof_no,
                                               self.prev_hash, self.data,
                                               self.timestamp)


class BlockChain:

    def __init__(self):
        self.chain : list[Block] = []
        self.current_data = []
        self.nodes = set()
        self.construct_genesis()

    def construct_genesis(self):
        self.construct_block(proof_no=0, prev_hash=0)

    def construct_block(self, proof_no, prev_hash):
        block = Block(
            index=len(self.chain),
            proof_no=proof_no,
            prev_hash=prev_hash,
            data=self.current_data)
        self.current_data = []

        self.chain.append(block)
        return block

    @staticmethod
    def check_validity(block : Block, prev_block : Block):
        if prev_block.index + 1 != block.index:
            return False

        elif prev_block.calculate_hash() != block.prev_hash:
            return False

        elif not BlockChain.verifying_proof(block.proof_no,
                                            prev_block.proof_no):
            return False

        elif block.timestamp <= prev_block.timestamp:
            return False

        return True
    
    def check_chain_validity():
        # TODO
        pass

    def new_data(self, sender, recipient, quantity):
        self.current_data.append({
            'sender': sender,
            'recipient': recipient,
            'quantity': quantity
        })
        return True

    @staticmethod
    def proof_of_work(last_proof):
        '''this simple algorithm identifies a number f' such that hash(ff') contain 4 leading zeroes
         f is the previous f'
         f' is the new proof
        '''
        proof_no = 0
        while BlockChain.verifying_proof(proof_no, last_proof) is False:
            proof_no += 1

        return proof_no

    @staticmethod
    def verifying_proof(last_proof, proof):
        # verifying the proof: does hash(last_proof, proof) contain enough leading zeroes?

        guess = f'{last_proof}{proof}'.encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        return guess_hash[:4] == '0' * DIFFICULTY

    @property
    def latest_block(self):
        return self.chain[-1]

    def block_mining(self, details_miner):

        self.new_data(
            sender="0",  # it implies that this node has created a new block
            receiver=details_miner,
            # creating a new block (or identifying the proof number) is awarded with 1
            quantity=1,
        )

        last_block = self.latest_block

        last_proof_no = last_block.proof_no
        proof_no = self.proof_of_work(last_proof_no)

        last_hash = last_block.calculate_hash
        block = self.construct_block(proof_no, last_hash)

        return vars(block)

    def create_node(self, address):
        self.nodes.add(address)
        return True

    @staticmethod
    def obtain_block_object(block_data):
        # obtains block object from the block data

        return Block(
            block_data['index'],
            block_data['proof_no'],
            block_data['prev_hash'],
            block_data['data'],
            timestamp=block_data['timestamp'])

class Transaction:
    def __init__(self, sender, receiver, amount):
        self.sender = sender
        self.receiver = receiver
        self.amount = amount

class User:
    def __init__(self, uid, blockchain : BlockChain) -> None:
        self.uid = uid
        self.blockchain = blockchain

    def calculate_balance(self):
        user_balance = 0
        for block in self.blockchain.chain:
            for data in block.data:
                # print(data)
                if data["recipient"] == self.user:
                    user_balance = user_balance + float(data["quantity"])
                elif data["sender"] == self.user:
                    user_balance = user_balance - float(data["quantity"])
        return user_balance
    
    # TODO - define user_object vs user_id
    def send_currency(self, receiver, amount):
        balance = self.calculate_balance()
        if amount > balance:
            return False
        else:
            # add sign transaction
            # find way to implement transaction handling - how are we adding these to the chain?
            transaction = Transaction(self.uid, receiver, amount)
            # going to need to add to pool in Network, and then let all miners add those to the chain
            return True
    
class Network:
    def __init__(self):
        self.nodes : list[Node] = []
        self.blockchain : BlockChain = BlockChain()
        self.unresolved_transactions : list[Transaction] = []

    def register_node(self, node):
        self.nodes.append(node)

    def add_transaction(self, transaction : Transaction):
        self.unresolved_transactions.append(transaction)

    def get_blockchain(self):
        return self.blockchain
    
    def get_unresolved_transaction(self):
        return self.unresolved_transactions[0]

    def broadcast(self):
        longest_chain = None
        max_length = len(self.blockchain.chain)
        
        # Get the longest valid blockchain from the network
        # TODO - add verification steps
        for node in self.nodes:
            length = len(node.blockchain.chain)
            if length > max_length and self.blockchain.check_chain_validity(node.blockchain.chain):
                max_length = length
                longest_chain = node.blockchain.chain
        
        # If the longest blockchain in the network is not the current node's blockchain, replace it
        if longest_chain:
            self.blockchain = longest_chain
            return True
        else:
            return False
        
    def update_nodes(self):
        for node in self.nodes:
            node.receive_broadcast(self.blockchain)

    def consensus(self):
        # This function will use the broadcast function to resolve conflicts
        self.broadcast()

    def broadcast_mined(self, proposed_blockchain : BlockChain):
        if len(proposed_blockchain.chain) > len(self.blockchain) and proposed_blockchain.check_validity == True:
            self.blockchain = proposed_blockchain
            self.update_nodes()

class Node:
    def __init__(self, user) -> None:
        self.user = user
        self.blockchain = None
        self.network : Network = None

    def connect_to_network(self, network : Network):
        self.network = network
        network.register_node(self)
        self.blockchain = network.get_blockchain

    def receive_broadcast(self, blockchain : BlockChain):
        self.blockchain = blockchain

    def mine(self, num_iterations : int = -1):
        if num_iterations > 0:
            for i in range (num_iterations):
                self._mine(self.blockchain, self.user)
        else:
            while(True):
                self._mine(self.blockchain, self.user)

    def _mine(self, blockchain : BlockChain, user):
        last_block = blockchain.latest_block
        last_proof_no = last_block.proof_no
        proof_no = blockchain.proof_of_work(last_proof_no)

        blockchain.new_data(
            sender = "0",  # it implies that this node has created a new block
            recipient = user,
            # creating a new block (or identifying the proof number) is awarded with 1
            quantity=1,
        )

        last_hash = last_block.calculate_hash
        # TODO: ensure that current block in sequence hasn't already been mined
        # do this by checking sequential block numbers/IDs
        block = blockchain.construct_block(proof_no, last_hash)

        blockchain.chain.append(block)

        if self.network.broadcast(blockchain) == True:
            print("Mined successfully!")

        
def main():
    pass
    """
    PLAN FOR MAIN:
    - make two users
    - mine a block
    - move mined currency to other account
    - demo network
    - basically just run through documentation's FR list and show that each item works
    """

    network = Network()
    user_bob = User("bob", network.blockchain)
    user_alice = User("alice", network.blockchain)

    # TODO - rectify user_string vs user_object issues
    node_bob = Node("bob")
    node_bob.connect_to_network(network)
    node_bob.mine()

    bob_initial_balance = user_bob.calculate_balance() # should be 1 as reward for mining
    alice_initial_balance = user_alice.calculate_balance # should be 0

    # TODO add transaction signing and sending logic to user_object
    # do a transaction and prove that the money was sent
    

if __name__ == "__main__":
    main()
