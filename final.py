from datetime import datetime
import hashlib
import ecdsa
from ecdsa import SigningKey, VerifyingKey
import copy

CHALLENGE_MESSAGE = "Success!"
MINING_REWARD = 1.0
DIFFICULTY = 2
LEADING_CHARACTERS = '0'

class User:
    def __init__(self):
        self.private_key : SigningKey = SigningKey.generate(curve=ecdsa.SECP256k1)
        self.public_key : VerifyingKey = self.private_key.get_verifying_key()
        self.signature = self.private_key.sign_deterministic(CHALLENGE_MESSAGE.encode('utf-8')).hex()

    # For verification purposes:
    # Checks that a provided private key's signature and the original signature match.
    def test_challenge(self, private_key : SigningKey):
        testing_data = private_key.sign_deterministic(CHALLENGE_MESSAGE.encode('utf-8')).hex()
        # print("Testing data: " + testing_data + "\nSignature: " + self.signature)
        if self.signature == testing_data:
            return True
        else:
            return False
    
    # TODO: make "private_key" a hidden attribute later on.
    def get_public_key(self):
        return self.public_key
        

class Transaction:
    def __init__(self, amount : float, sender : User, receiver : User) -> None:
        self.amount : float = amount
        self.sender : User = sender
        self.receiver : User = receiver
        self.timestamp : datetime = datetime.now()
        self.signature = None

    def get_basic_representation(self) -> str:
        s : str = str(self.amount) + " sent by " + str(self.sender.public_key.to_string()) + " to " + str(self.receiver.public_key.to_string()) + " at " + str(self.timestamp)
        return s
    
    def get_hash(self) -> str:
        message = self.get_basic_representation()
        hashed_message = hashlib.sha256(message.encode('utf-8')).hexdigest()
        return hashed_message
    
    # Transaction is signed by taking a hash of the representation of the transaction, and then signing that with the private key.
    # To verify the transaction, one must use the public (verifying) key to unencrypt the signature and note that the hash is the ...
    # ... same as the calculated hash.
    def sign_transaction(self, private_key : SigningKey):
        hashed_message : str = self.get_hash()
        signature = private_key.sign_deterministic(data=hashed_message.encode('utf-8'))
        self.signature = signature
        return signature
    
    def get_complete_representation(self) -> str:
        s : str = str(self.amount) + " sent by " + str(self.sender.public_key.pubkey) + " to " + str(self.receiver.public_key.pubkey) + " at " + str(self.timestamp)
        return s
    
    # Check that signature decodes to the same thing as the calcualted hash of the transaction.
    def verify_transaction(self, public_key : VerifyingKey):
        own_hash = self.get_hash()
        if self.signature is None:
            print("Transaction not signed!")
            return False
        return public_key.verify(signature=self.signature, data=own_hash.encode('utf-8'))


class Block:
    def __init__(self, index : int = -1, prev_hash : str = "") -> None:
        self.transactions : list[Transaction] = []
        self.index : int = index
        self.timestamp = datetime.now()
        self.prev_hash : str = prev_hash
        self.nonce = ""

    # First, calculate hash of transactions, to string format.
    # Secondly, make a new string combining that hash with the other data contained in the block.
    # Lastly, then, hash that new string and return the resultant hash value.
    def calculate_hash(self) -> str :
        hashed_transactions : str = hashlib.sha256(str(self.transactions).encode('utf-8')).hexdigest()
        combined_string : str = hashed_transactions + str(self.index) + str(self.timestamp) + self.prev_hash + str(self.nonce)
        final_hash : str = hashlib.sha256(combined_string.encode('utf-8')).hexdigest()
        return final_hash

    # Used in future by "mining" method - once a block has been constructed, it must verify that block. Only then...
    # ... can it add its own transaction to the block, as a reward.
    # Iterate through all transactions in a block, and run "verify_transaction" on each.
    # Each transaction stores the identity of the sender, who signed the transaction, in the "sender" attribute.
    # Using that "sender" object, get their public key, and feed it into the "verify_transaction" method.
    # If any transaction if incorrect, abort the check and return False: otherwise, return True.
    def verify_block(self) -> bool:
        if self.index == 0:
            print("Genesis block always verified.")
            return True

        for transaction in self.transactions:
            t_pk : VerifyingKey = transaction.sender.get_public_key()
            # print(transaction.get_basic_representation())
            if t_pk is None:
                print("Public key of superuser is None!")
                exit()
            if transaction.signature == None:
                print("Transaction signature is None in verify_block! " + str(self.index))
                exit()
            if transaction.verify_transaction(t_pk) == False:
                print("Failed to verify block!")
                return False
        print("Block verified.")
        return True
    
    def add_transaction(self, t : Transaction) -> None:
        try:
            self.transactions.append(t)
        except:
            print("Error in adding transaction!")

    def set_nonce(self, nonce : int):
        self.nonce = nonce
    

class Blockchain:
    def __init__(self) -> None:
        self.chain : list[Block] = []
        self.chain_hash : str = "" # was going to do a Merkle tree, but this was an easier and equally viable solution

    # Iterates through whole chain, using each block's "verify_block" method.
    def check_chain_validity(self) -> bool:
        i : int = 0
        prev_hash = ""
        for block in self.chain:
            if block.verify_block() == False:
                print("Blockchain unverifiable! Error at block index " + str(i))
                return False
            if block.index > 0:
                if block.prev_hash != prev_hash:
                    print("Blockchain invalid due to past block mismatch! Error at block index " + str(i))
                    print(str(block.prev_hash) + " vs. " + str(prev_hash))
                    return False
            prev_hash = block.calculate_hash()
            i = i + 1
        return True
    
    # Calculates fresh value of chain hash and returns it as a string
    # TODO - contemplate whether Merkle root would prevent overly-long strings from being unhashable in the future
    def get_chain_hash(self) -> str:
        # first, add all blocks' hashes together
        s : str = ""
        for block in self.chain:
            s = s + block.calculate_hash()
        
        # then calculate overall hash
        h : str = hashlib.sha256(s.encode('utf-8')).hexdigest()

        return h
    
    # Calculates current value of chain hash using "get_chain_hash", and then...
    # ...checks whether it's the same as the provided root, returning True if it is and False if not.
    def verify_chain_hash(self, proposed_root_hash) -> bool:
        calculated_root_hash = self.get_chain_hash()
        if calculated_root_hash == proposed_root_hash:
            return True
        else:
            print("Incorrect root hash provided!")
            return False

    # Calculates chain hash using "get_chain_hash" and then updates this blockchain's merkle root attribute
    # TODO - contemplate whether this should even be a stored field, or only a calculated one?
    def update_chain_hash(self) -> None:
        self.chain_hash = self.get_chain_hash()


    def add_block(self, block : Block):
        try:
            if len(self.chain) > 0:
                block.prev_hash = self.chain[-1].calculate_hash()
            block.index = len(self.chain)
            self.chain.append(block)
            self.update_chain_hash()
        except:
            print("Error adding new block to chain!")
    
    # Simply checks whether there are already blocks in the chain, and if not, then it constructs the genesis block.
    def construct_genesis(self) -> bool:
        if len(self.chain) == 0:
            genesis_block = Block(0, "")
            self.chain.append(genesis_block)
            self.update_chain_hash()
            return True
        else:
            print("Can't construct genesis block: chain already has blocks.")
            return False

# For demo purposes, create the network and add a transaction to the pool, then run the miner and make a new block that includes that transaction.
class Network:
    def __init__(self, blockchain : Blockchain) -> None:
        self.blockchain : Blockchain = blockchain
        self.unresolved_transactions : list[Transaction] = []
        self.network_superuser = User()

    def add_transaction(self, t : Transaction) -> None:
        try:
            self.unresolved_transactions.append(t)
        except:
            print("Error adding transaction to unresolved transaction list!")

    # Not requesting signature as parameter as this function makes the transaction sign itself as it is generated, and before it enters...
    # ... the pool of unsigned transactions.
    def create_transaction(self, sender : User, reciever : User, amount : float) -> Transaction:
        try:
            t : Transaction = Transaction(amount=amount, sender=sender, receiver=reciever)
            t.sign_transaction
            self.add_transaction(t)
            return t
        except:
            print("Error creating transaction in network!")
            return None
        
    def get_unresolved_transactions(self):
        return self.unresolved_transactions
        
    def update_chain(self, b : Blockchain):
        if b.check_chain_validity and len(b.chain) > len(self.blockchain.chain):
            self.blockchain = b
        else:
            print("Rejected newly mined chain! Either invalid or shorter than existing chain.")


# Note: Node wil always consult to Network, but Network never needs to consult individual Nodes.
# This is to avoid issues when Nodes disconnect, and also to avoid circular dependencies.
class Node:
    def __init__(self, blockchain : Blockchain, user : User, network = None) -> None:
        self.blockchain : Blockchain = copy.deepcopy(blockchain)
        self.user : User = user
        self.network : Network = network

    def connect(self, n) -> None:
        self.network = n

    # Mining method must check the length of its network's chain before pushing the one it is working on...
    # ... and update its own chain to the the network's current chain if its one is shorter.
    def mine(self, num_iterations : int):
        for i  in range (num_iterations):
            # get all existing unfinished transactions
            transaction_list = self.network.get_unresolved_transactions()
            # add them all to the new block
            new_block = Block(index=len(self.blockchain.chain))
            for transaction in transaction_list:
                transaction.sign_transaction(transaction.sender.private_key)
                new_block.add_transaction(transaction)

            # add one extra transaction with own reward
            reward_transaction = Transaction(amount=MINING_REWARD, sender=self.network.network_superuser, receiver=self.user)
            reward_transaction.sign_transaction(self.network.network_superuser.private_key)
            if reward_transaction.signature == None:
                print("Reward transaction still has no signature!")
                exit()
            new_block.add_transaction(reward_transaction)
            if reward_transaction.verify_transaction(self.network.network_superuser.get_public_key()) == False:
                print("Reward transaction unverifiable!")
                exit()
            if new_block.transactions[-1].signature == None:
                print("New block's last transaction signature is None!")
                exit()
            if new_block.verify_block() == False:
                print("Error in verifying new block!")
                break
            
            print("Block made, now to calculate nonce...")

            # now work out hash with nonce
            n = 0
            h = new_block.calculate_hash()
            while h[ 0:DIFFICULTY ] != LEADING_CHARACTERS * DIFFICULTY:
                n = n + 1
                # print("Testing with nonce: " + str(n))
                new_block.set_nonce(n)
                h = new_block.calculate_hash()

            print("Success - found correct nonce: " + str(n) + ", producting hash " + str(h))

            # add new block to chain
            self.blockchain.add_block(new_block)

            print("Own blockchain updated with new block.")
            print("New chain length: " + str(len(self.blockchain.chain)))
            print("Network blockchain length: " + str(len(self.network.blockchain.chain)))

            # now check if network chain is shorter than new chain
            if len(self.network.blockchain.chain) < len(self.blockchain.chain):
                print("Updating blockchain - broadcast time.")
                self.network.update_chain(self.blockchain)
                print("Node completed mining process successfully.")
            else:
                break

def main():
    bob : User = User()
    alice : User = User()

    print("Let's first check that Bob is who he says he is...")
    bob_login : bool = bob.test_challenge(bob.private_key)
    if bob_login == True:
        print("Bob successfully logged in.")
    else:
        print("Bob is an imposter!")

    print("Let's not create a transaction: not going to be used on the network, but just to be sure transactions can be created correctly.")
    bobs_first_transaction : Transaction = Transaction(amount=10, sender=bob, receiver=alice)
    bobs_first_transaction.sign_transaction(bob.private_key)
    print(bobs_first_transaction.get_complete_representation())

    print("Does the transaction verify correctly?")
    transaction_verification : bool = bobs_first_transaction.verify_transaction(bob.public_key)
    if transaction_verification == True:
        print("Transaction verified.")
    else:
        print("Transaction fraudulent!")

    print("Let's test the Block class out now...")
    block = Block(1)
    block.add_transaction(bobs_first_transaction)
    print("Does the block verify?")
    if block.verify_block():
        print("It does.")
    else:
        print("It does not - block unverifiable!")
    
    print("Now let's see the blockchain itself working:")
    bchain = Blockchain()
    bchain.construct_genesis()
    bchain.add_block(block)
    for block in bchain.chain:
        print(block.index)
    print("Does the blockchain verify?")
    verification : bool = bchain.check_chain_validity()
    if verification:
        print("It does.")
    else:
        print("It does not.")

    
    print("Let's see if the Network can be generated now...")
    network : Network = Network(bchain)
    for block in network.blockchain.chain:
        print(block.index)

    network.create_transaction(bob, alice, 0.5)

    print("With the Network seemingly working, we now have to test the Nodes that are connected to it.")

    node : Node = Node(network.blockchain, bob, network)
    
    print("Network chain length: " + str(len(network.blockchain.chain)))

    node.mine(1)

if __name__ == "__main__":
    main()

"""
CHECKLIST:
    Write classes:
        User        - Done
        Transaction - Done
        Block       - Done
        Blockchain  - Done
        Node        - Done
        Network     - Done

    Test classes:
        User        - Done
        Transaction - Done
        Block       - Done
        Blockchain  - Done
        Node        - TODO
        Network     - TODO

    Develop demo:   - TODO

    Record demo:    - TODO

    Generate UML:   - Done
"""