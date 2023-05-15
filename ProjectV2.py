import hashlib
import random
import string
import json
import binascii
import numpy as np
import pandas as pd
import pylab as pl
import logging
import datetime
import collections

import Cryptodome
import Cryptodome.Random
from Cryptodome.Hash import SHA256
from Cryptodome.Hash import SHA
from Cryptodome.PublicKey import RSA
from Cryptodome.Signature import PKCS1_v1_5

class Client:
    def __init__(self):
        random = Cryptodome.Random.new().read
        self._private_key = RSA.generate(1024, random)
        self._public_key = self._private_key.publickey()
        self._signer = PKCS1_v1_5.new(self._private_key)

    @property
    def identity(self):
        return binascii.hexlify(self._public_key.exportKey(format='DER')).decode('ascii')

class Transaction:
    def __init__(self, sender, recipient, value):
        self.sender = sender
        self.recipient = recipient
        self.value = value
        self.time = datetime.datetime.now()
        self.signature = None

    def to_dict(self):
        if self.sender == "Genesis":
            identity = "Genesis"
        else:
            identity = self.sender.identity
        
        return collections.OrderedDict({
            'sender' : identity,
            'recipient': self.recipient,
            'value': self.value,
            'time': self.time
        })
    
    def sign_transaction(self):
        private_key = self.sender._private_key
        signer = PKCS1_v1_5.new(private_key)
        hash = SHA256.new(str(self.to_dict()).encode('utf8'))
        self.signature = binascii.hexlify(signer.sign(hash)).decode('ascii')
        return self.signature
    
    def verify_transaction(self):
        if self.sender == "Genesis":
            return True

        public_key = RSA.importKey(binascii.unhexlify(self.sender))
        verifier = PKCS1_v1_5.new(public_key)
        hash = SHA256.new(str(self.to_dict()).encode('utf8'))
        return verifier.verify(hash, binascii.unhexlify(self.sign_transaction()))

class Block:
    def __init__(self) -> None:
        self.verified_transactions = []
        self.previous_block_hash = ""
        self.Nonce = ""

def sha256(message):
    return hashlib.sha256(message.encode('ascii')).hexdigest()

def mine(message, difficulty=1):
    assert difficulty >= 1
    prefix = '1' * int(difficulty)
    print("Prefix: " + str(prefix))
    i = 0
    while True:
        digest = sha256(str(hash(message)) + str(i))
        # print("Digest: " + digest)
        if digest.startswith(prefix):
            print("After " + str(i) + " iterations found nonce: " + digest)
            break
        i = i + 1
    return digest

def display_transactions(transactions):
    for transaction in transactions:
        dict = transaction.to_dict()
        print ("sender: " + dict['sender'])
        print ('-----')
        print ("recipient: " + dict['recipient'])
        print ('-----')
        print ("value: " + str(dict['value']))
        print ('-----')
        print ("time: " + str(dict['time']))
        print ('-----')

def main():
    transactions = []
    last_block_hash = ""
    TPCoins = []
    last_transaction_index = 0

    block = Block()

    for i in range(3):
        temp_transaction = transactions[last_transaction_index]
        
        
        #TODO - validate transaction
        if not temp_transaction.verify_transaction():
            print("Invalid transaction")
            exit

        block.verified_transactions.append(temp_transaction)
        last_transaction_index = last_transaction_index + 1
    
    block.previous_block_hash = last_block_hash
    block.Nonce = mine(block, 2)
    digest = hash(block)
    TPCoins.append(block)
    last_block_hash = digest

if __name__ == "__main__":
    main()