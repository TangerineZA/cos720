from datetime import datetime
import hashlib
import ecdsa
from ecdsa import SigningKey, VerifyingKey

CHALLENGE_MESSAGE = "Success!"

class User:
    def __init__(self):
        self.private_key : SigningKey = SigningKey.generate(curve=ecdsa.SECP256k1)
        self.public_key : VerifyingKey = self.private_key.get_verifying_key()
        self.signature = self.private_key.sign_deterministic(CHALLENGE_MESSAGE.encode('utf-8')).hex()

    # For verification purposes:
    # Checks that a provided private key's signature and the original signature match.
    def test_challenge(self, private_key : SigningKey):
        testing_data = private_key.sign_deterministic(CHALLENGE_MESSAGE.encode('utf-8')).hex()
        print("Testing data: " + testing_data + "\nSignature: " + self.signature)
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
        s : str = str(self.amount) + " sent by " + str(self.sender.public_key) + " to " + str(self.receiver.public_key) + " at " + str(self.timestamp)
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
        if self.signature == None:
            print("Transaction not signed!")
            return False
        return public_key.verify(signature=self.signature, data=own_hash.encode('utf-8'))


class Block:
    def __init__(self, index : int = -1, prev_hash : str = "") -> None:
        self.transactions : list[Transaction] = []
        self.index : int = index
        self.timestamp = datetime.now()
        self.prev_hash : str = prev_hash

    # TODO - test this method
    # First, calculate hash of transactions, to string format.
    # Secondly, make a new string combining that hash with the other data contained in the block.
    # Lastly, then, hash that new string and return the resultant hash value.
    def calculate_hash(self) -> str :
        hashed_transactions : str = hashlib.sha256(str(self.transactions).encode('utf-8')).hexdigest()
        combined_string : str = hashed_transactions + str(self.index) + str(self.timestamp) + self.prev_hash
        final_hash : str = hashlib.sha256(combined_string.encode('utf-8')).hexdigest()
        return final_hash

    # TODO - test method
    # Used in future by "mining" method - once a block has been constructed, it must verify that block. Only then...
    # ... can it add its own transaction to the block, as a reward.
    # Iterate through all transactions in a block, and run "verify_transaction" on each.
    # Each transaction stores the identity of the sender, who signed the transaction, in the "sender" attribute.
    # Using that "sender" object, get their public key, and feed it into the "verify_transaction" method.
    # If any transaction if incorrect, abort the check and return False: otherwise, return True.
    def verify_block(self) -> bool:
        for transaction in self.transactions:
            t_pk : VerifyingKey = transaction.sender.get_public_key()
            if transaction.verify_transaction(t_pk) == False:
                print("Failed to verify block!")
                return False
        print("Block verified!")
        return True

def main():
    bob : User = User()
    alice : User = User()

    print("Let's first check that Bob is who he says he is...")
    bob_login : bool = bob.test_challenge(bob.private_key)
    if bob_login == True:
        print("Bob successfully logged in!")
    else:
        print("Bob is an imposter!")

    print("\n\n")

    print("Let's not create a transaction: not going to be used on the network, but just to be sure transactions can be created correctly.")
    bobs_first_transaction : Transaction = Transaction(amount=10, sender=bob, receiver=alice)
    bobs_first_transaction.sign_transaction(bob.private_key)
    print(bobs_first_transaction.get_complete_representation())

    print("\n\n")

    print("Does the transaction verify correctly?")
    transaction_verification : bool = bobs_first_transaction.verify_transaction(bob.public_key)
    if transaction_verification == True:
        print("Transaction verified!")
    else:
        print("Transaction fraudulent!")


    

if __name__ == "__main__":
    main()

"""
CHECKLIST:
    Write classes:
        User        - Done
        Transaction - Done
        Block       - Done
        Blockchain  - TODO
        Node        - TODO
        Network     - TODO

    Test classes:
        User        - Done
        Transaction - Done
        Block       - TODO
        Node        - TODO
        Network     - TODO

    Develop demo:   - TODO

    Record demo:    - TODO

    Generate UML:   - TODO
"""