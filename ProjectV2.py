import hashlib
import datetime as datetime

class Block:
    def __init__(self, index, timestamp, data, previous_hash) -> None:
        self.index = index
        self.timestamp = timestamp
        self.data = data
        self.previous_hash = previous_hash
        self.hash = self.hash_block()

    def hash_block(self):
        """Creates the unique hash for the block. It uses sha256."""
        sha256 = hashlib.sha256()
        sha256.update((str(self.index) + str(self.timestamp) + str(self.data) + str(self.previous_hash)).encode('utf-8'))
        return sha256.hexdigest()

class Miner:
    def __init__(self) -> None:
        self.blockchain = [self.create_genesis_block()]
        self.pending_transactions = []

    def create_genesis_block(self):
        return Block(0, datetime.datetime.now(), {
            "proof-of-work": 9,
            "transactions": None},
            "0")
    
    def proof_of_work(last_proof, blockchain):
        # Creates a variable that we will use to find our next proof of work
        incrementer = last_proof + 1
        # Keep incrementing the incrementer until it's equal to a number divisible by 7919
        # and the proof of work of the previous block in the chain
        start_time = datetime.datetime.now()
        while not (incrementer % 7919 == 0 and incrementer % last_proof == 0):
            incrementer += 1
            # Check if any node found the solution every 60 seconds
            if int((time.time()-start_time) % 60) == 0:
                # If any other node got the proof, stop searching
                new_blockchain = consensus(blockchain)
                if new_blockchain:
                    # (False: another node got proof first, new blockchain)
                    return False, new_blockchain
        # Once that number is found, we can return it as a proof of our work
        return incrementer, blockchain