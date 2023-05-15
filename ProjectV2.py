from ecdsa import SigningKey, NIST256p, VerifyingKey, BadSignatureError
from hashlib import sha256
from ecdsa.util import sigencode_der
from datetime import datetime
import threading

class Block:
    def __init__(self, hash, previous_hash, timestamp, transaction_data, nonce = 0) -> None:
        self.hash = hash
        self.previous_hash = previous_hash
        self.timestamp = timestamp
        self.transaction_data = transaction_data
        self.nonce = nonce

    def __repr__(self) -> str:
        return f"Block(hash={self.hash}, previous_hash={self.previous_hash}, timestamp={self.timestamp}, transaction_data={self.transaction_data}, nonce={self.nonce})"
    
class Transaction:
    def __init__(self, sender, recipient, amount, signature):
        self.sender = sender
        self.recipient = recipient
        self.amount = amount
        self.signature = signature

    def __repr__(self):
        return f"Transaction(sender={self.sender}, recipient={self.recipient}, amount={self.amount}, signature={self.signature})"

class Wallet:
    def __init__(self, public_key : VerifyingKey, private_key : SigningKey, balance = 0):
        self.public_key = public_key
        self.private_key = private_key
        self.balance = balance

    def get_balance(self):
        return self.balance

    def send_transaction(self, recipient_key, amount):
        if self.balance < amount:
            raise ValueError("Insufficient balance")

        # Create a new transaction and sign it
        transaction = Transaction(
            sender=self.public_key,
            recipient=recipient_key,
            amount=amount,
            signature=None,  # We'll sign it next
        )
        transaction.signature = self.sign_transaction(str(transaction).encode())

        # Subtract the amount from the wallet's balance
        self.balance -= amount

        return transaction


    def sign_transaction(self, transaction):
        signature = self.private_key.sign_deterministic(
            transaction,
            hashfunc=sha256,
            sigencode=sigencode_der
        )
        return signature

    def verify_transaction(self, transaction, signature):
        try:
            ret = self.public_key.verify(signature, transaction, sha256, sigdecode=sigencode_der)
            assert ret
            return True
        except BadSignatureError:
            return False

class Network:
    def __init__(self):
        self.miners = []
        self.blockchain = []

    def add_miner(self, miner):
        self.miners.append(miner)

    def add_block(self, block):
        self.blockchain.append(block)

    def broadcast_block(self, block):
        for miner in self.miners:
            miner.receive_block(block)

    def receive_block(self, block):
        if not self.is_valid_block(block):
            return

        self.add_block(block)

    def is_valid_block(self, block):
        if block.hash is None:
            return False

        if block.previous_hash != self.get_previous_hash():
            return False

        if block.timestamp < datetime.now() - datetime.timedelta(seconds=1):
            return False

        if not self.verify_transactions(block.transaction_data):
            return False

        return True

    def verify_transactions(self, transactions):
        for transaction in transactions:
            if not self.wallet.verify_transaction(transaction):
                return False

        return True

    def get_previous_hash(self):
        if len(self.blockchain) == 0:
            return "0"

        return self.blockchain[-1].hash

    def get_balance(self, wallet):
        total = 0

        for block in self.blockchain:
            for transaction in block.transaction_data:
                if transaction.sender == wallet.public_key:
                    total -= transaction.amount

                if transaction.recipient == wallet.public_key:
                    total = total + transaction.amount

        return total
    
    def broadcast_transaction(self, transaction):
        # Create a new block with the transaction
        block = Block(
            hash=None,
            previous_hash=self.get_previous_hash(),
            timestamp=datetime.now(),
            transaction_data=[transaction],
            nonce=None,
        )

        # Broadcast the block to all miners
        self.broadcast_block(block)

    def share_blockchain(self):
        return self.blockchain

class Miner:
    def __init__(self, wallet, reward = 1, network : Network=None, blockchain=None):
        self.wallet = wallet
        self.reward = reward
        if network == None:
            self.network = Network()
        if blockchain== None:
            self.blockchain = self.network.share_blockchain()
        self.threads = []

    def mine_block(self, transactions, num_threads = 10):
        for i in range(num_threads):
            thread = threading.Thread(target=self._mine_block, args=(transactions,))
            thread.start()
            self.threads.append(thread)
            i = i + 1

        for thread in self.threads:
            thread.join()

    def _mine_block(self, transactions):
        block = Block(
            hash=None,
            previous_hash=self.get_previous_hash(),
            timestamp=datetime.now(),
            transaction_data=transactions,
            nonce=None,
        )

        while not self.is_valid_block(block):
            block.nonce = block.nonce + 1

        self.add_block_to_chain(block)

        if self.is_valid_block(block):
            self.wallet.add_balance(self.reward)

    def get_previous_hash(self):
        if len(self.blockchain) == 0:
            return "0"

        return self.blockchain[-1].hash

    def is_valid_block(self, block):
        if block.hash is None:
            return False

        if block.previous_hash != self.get_previous_hash():
            return False

        if block.timestamp < datetime.now() - datetime.timedelta(seconds=1):
            return False

        if not self.verify_transactions(block.transaction_data):
            return False

        return True
    
    def receive_block(self, block):
        if self.is_valid_block(block):
            self.blockchain.append(block)

    def add_block_to_chain(self, block):
        self.blockchain.append(block)

    def verify_transactions(self, transactions):
        for transaction in transactions:
            if not self.wallet.verify_transaction(transaction):
                return False

        return True

def main():
    # Generate keys for Alice and Bob
    alice_private_key = SigningKey.generate(curve=NIST256p)
    alice_public_key = alice_private_key.get_verifying_key()
    bob_private_key = SigningKey.generate(curve=NIST256p)
    bob_public_key = bob_private_key.get_verifying_key()

    # Create wallets for Alice and Bob
    alice_wallet = Wallet(alice_public_key, alice_private_key, balance=50)
    bob_wallet = Wallet(bob_public_key, bob_private_key, balance=0)

    # Create a miner with a wallet
    miner_private_key = SigningKey.generate(curve=NIST256p)
    miner_public_key = miner_private_key.get_verifying_key()
    miner_wallet = Wallet(miner_public_key, miner_private_key, balance=0)
    miner = Miner(miner_wallet)

    # Create a Network
    network = Network()
    network.add_miner(miner)

    # Alice sends 10 coins to Bob
    transaction = alice_wallet.send_transaction(bob_wallet.public_key, 10)
    network.broadcast_transaction(transaction)
    print(f"Alice sent 10 coins to Bob: {transaction}")

    # Miner mines a block with the transaction
    # miner.mine_block([transaction])
    # print(f"Miner mined a block: {network.blockchain[-1]}")

    # Check balances
    print(f"Alice's balance: {network.get_balance(alice_wallet)}")
    print(f"Bob's balance: {network.get_balance(bob_wallet)}")
    #  print(f"Miner's balance: {network.get_balance(miner_wallet)}")

if __name__ == "__main__":
    main()