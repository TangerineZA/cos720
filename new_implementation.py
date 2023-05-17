
import hashlib
import time

# global variabile for difficulty
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
    def check_validity(block, prev_block):
        if prev_block.index + 1 != block.index:
            return False

        elif prev_block.calculate_hash != block.prev_hash:
            return False

        elif not BlockChain.verifying_proof(block.proof_no,
                                            prev_block.proof_no):
            return False

        elif block.timestamp <= prev_block.timestamp:
            return False

        return True

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

def calculate_balance(blockchain : BlockChain, user):
    user_balance = 0
    for block in blockchain.chain:
        for data in block.data:
            # print(data)
            if data["recipient"] == user:
                user_balance = user_balance + float(data["quantity"])
            elif data["sender"] == user:
                user_balance = user_balance - float(data["quantity"])
    return user_balance

def mine(blockchain : BlockChain, user, num_iterations : int = -1):
    if num_iterations > 0:
        for i in range (num_iterations):
            _mine(blockchain, user)
    else:
        while(True):
            _mine(blockchain, user)

def _mine(blockchain : BlockChain, user):
    last_block = blockchain.latest_block
    last_proof_no = last_block.proof_no
    proof_no = blockchain.proof_of_work(last_proof_no)

    blockchain.new_data(
        sender="0",  # it implies that this node has created a new block
        recipient=user,
        # creating a new block (or identifying the proof number) is awarded with 1
        quantity=1,
    )

    last_hash = last_block.calculate_hash
    block = blockchain.construct_block(proof_no, last_hash)

    print("Mined successfully!")

def main():
    blockchain = BlockChain()

    print("***Mining fccCoin about to start***")
    print(blockchain.chain)

    last_block = blockchain.latest_block
    last_proof_no = last_block.proof_no
    proof_no = blockchain.proof_of_work(last_proof_no)

    blockchain.new_data(
        sender="0",  # it implies that this node has created a new block
        recipient="John",  # let's send John some coins!
        # creating a new block (or identifying the proof number) is awarded with 1
        quantity=1,
    )

    last_hash = last_block.calculate_hash
    block = blockchain.construct_block(proof_no, last_hash)

    print("***Mining has been successful***")
    print(blockchain.chain)

    print("Let's create a transaction whereby John recieves 10 coins")
    blockchain.new_data(
        sender="0",  # it implies that this node has created a new block
        recipient="John",  # let's send Quincy some coins!
        # creating a new block (or identifying the proof number) is awarded with 1
        quantity=10,
    )

    last_hash = last_block.calculate_hash
    block = blockchain.construct_block(proof_no, last_hash)
    print("John's new balance: " + str(calculate_balance(blockchain, "John")))
    print(blockchain.chain)

    mine(blockchain=blockchain, user="John", num_iterations=2)
    print("John's new balance: " + str(calculate_balance(blockchain, "John")))

if __name__ == "__main__":
    main()
