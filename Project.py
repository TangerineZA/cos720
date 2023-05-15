import ecdsa
import datetime
import threading
import hashlib

class Block:
    def __init__(self, hash, previous_hash, timestamp, transaction_data, nonce) -> None:
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
    def __init__(self, public_key, private_key):
        self.public_key = public_key
        self.private_key = private_key
        self.balance = 0

    def get_balance(self):
        return self.balance

    def send_transaction(self, recipient, amount):
        if self.balance < amount:
            raise ValueError("Insufficient balance")

        transaction = Transaction(
            sender=self.public_key,
            recipient=recipient,
            amount=amount,
            signature=self.sign_transaction(transaction),
        )

        self.balance -= amount
        recipient.balance += amount

        return transaction

    def sign_transaction(self, transaction):
        return ecdsa.sign(transaction.to_bytes(), self.private_key)

    def verify_transaction(self, transaction):
        return ecdsa.verify(transaction.to_bytes(), transaction.signature, self.public_key)

class Miner:
    def __init__(self, wallet):
        self.wallet = wallet

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
            block.nonce += 1

        self.add_block_to_chain(block)

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

    def add_block_to_chain(self, block):
        self.blockchain.append(block)

    def verify_transactions(self, transactions):
        for transaction in transactions:
            if not self.wallet.verify_transaction(transaction):
                return False

        return True

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
                    total += transaction.amount

        return total

    def send_transaction(self, sender, recipient, amount):
        if self.get_balance(sender) < amount:
            raise ValueError("Insufficient balance")

        transaction = Transaction(
            sender=sender,
            recipient=recipient,
            amount=amount,
            signature=sender.sign_transaction(transaction),
        )

        self.broadcast_block(Block(
            hash=None,
            previous_hash=self.get_previous_hash(),
            timestamp=datetime.now(),
            transaction_data=[transaction],
            nonce=None,
        ))

        sender.balance -= amount
        recipient.balance += amount

        return transaction

class Crypto_helper:
    def __init__(self) -> None:
        self.sha256 = hashlib.sha256()

    def get_hash(self, data):
        self.sha256.update(data)
        return self.sha256.hexdigest()

def main():
    # Generate private and public keys
    private_key = generate_private_key
    public_key = generate_public_key(private_key=private_key)

    # Create a wallet with the private and public keys
    wallet = Wallet(private_key, public_key)

    # Create a miner
    miner = Miner(wallet)

    # Create a network
    network = Network()

    # Add the miner to the network
    network.add_miner(miner)

    # Start the miner
    miner.start()

    # Get the user's input
    while True:
        print("What would you like to do?")
        print("1. Mine")
        print("2. Make a transaction")
        print("3. Check your balance")
        print("4. Quit")

        choice = input()

        if choice == "1":
            print("Mining...")
            network.mine_block()

        elif choice == "2":
            print("Making a transaction...")
            recipient = input("Enter the recipient's public key: ")
            amount = input("Enter the amount to send: ")

            try:
                network.send_transaction(wallet, recipient, amount)
                print("Transaction sent successfully!")
            except ValueError as e:
                print(e)

        elif choice == "3":
            print("Your balance is:", wallet.balance)

        elif choice == "4":
            break



if __name__ == "__main__":
    main()