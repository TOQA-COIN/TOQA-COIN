import hashlib
import json
import time
import os
import sqlite3
import base58
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
from flask import Flask, jsonify, request

DB_FILE = os.getenv("TOQA_DB_FILE", "blockchain.db")
SECRET_KEY = os.getenv("TOQA_SECRET_KEY", Fernet.generate_key().decode())  
API_KEY = os.getenv("TOQA_API_KEY", "your_secure_api_key")  
MINING_REWARD = int(os.getenv("TOQA_MINING_REWARD", 50))  

cipher = Fernet(SECRET_KEY.encode())

conn = sqlite3.connect(DB_FILE, check_same_thread=False)
cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS blocks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    index INTEGER NOT NULL,
    timestamp REAL NOT NULL,
    proof INTEGER NOT NULL,
    previous_hash TEXT NOT NULL,
    transactions TEXT NOT NULL
)
""")
cursor.execute("""
CREATE TABLE IF NOT EXISTS wallets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    address TEXT NOT NULL UNIQUE,
    public_key TEXT NOT NULL,
    private_key TEXT NOT NULL
)
""")
conn.commit()

class TOQABlockchain:
    def __init__(self):
        self.mining_reward = MINING_REWARD
        self.transaction_fee_percentage = 0.01  
        self.transactions = []
        self.load_chain()

    def load_chain(self):
        cursor.execute("SELECT * FROM blocks")
        rows = cursor.fetchall()
        self.chain = [
            {
                'index': row[1],
                'timestamp': row[2],
                'proof': row[3],
                'previous_hash': row[4],
                'transactions': json.loads(row[5])
            }
            for row in rows
        ]
        if not self.chain:
            self.create_block(proof=1, previous_hash='0')

    def save_block(self, block):
        cursor.execute("""
        INSERT INTO blocks (index, timestamp, proof, previous_hash, transactions)
        VALUES (?, ?, ?, ?, ?)
        """, (block['index'], block['timestamp'], block['proof'], block['previous_hash'], json.dumps(block['transactions'])))
        conn.commit()

    def create_block(self, proof, previous_hash, miner_address=None):
        if miner_address:
            self.transactions.append({
                'sender': 'Network',
                'receiver': miner_address,
                'amount': self.mining_reward
            })
        block = {
            'index': len(self.chain) + 1,
            'timestamp': time.time(),
            'proof': proof,
            'previous_hash': previous_hash,
            'transactions': self.transactions
        }
        self.transactions = []
        self.chain.append(block)
        self.save_block(block)
        return block

    def create_wallet(self):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        public_key = private_key.public_key()
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        address = base58.b58encode_check(hashlib.sha256(public_pem).digest()).decode()

        encrypted_private_key = cipher.encrypt(private_pem)  
        cursor.execute("""
        INSERT INTO wallets (address, public_key, private_key)
        VALUES (?, ?, ?)
        """, (address, public_pem.decode(), encrypted_private_key.decode()))
        conn.commit()

        return {
            'address': address,
            'public_key': public_pem.decode(),
            'private_key': encrypted_private_key.decode()
        }

    def get_balance(self, address):
        balance = 0
        for block in self.chain:
            for transaction in block['transactions']:
                if transaction['receiver'] == address:
                    balance += transaction['amount']
                if transaction['sender'] == address:
                    balance -= transaction['amount']
        return balance

    def create_proof_of_work(self, previous_proof, range_start=1, range_end=1000000):
        new_proof = range_start
        while new_proof <= range_end:
            hash_operation = hashlib.sha256(str(new_proof**2 - previous_proof**2).encode()).hexdigest()
            if hash_operation[:4] == "0000":
                return new_proof
            new_proof += 1
        return None

    def hash(self, block):
        encoded_block = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(encoded_block).hexdigest()

app = Flask(__name__)
blockchain = TOQABlockchain()

@app.before_request
def validate_api_key():
    if request.headers.get("API-Key") != API_KEY:
        return jsonify({"error": "Unauthorized"}), 403

@app.route('/get_chain', methods=['GET'])
def get_chain():
    response = {'chain': blockchain.chain, 'length': len(blockchain.chain)}
    return jsonify(response), 200

@app.route('/create_wallet', methods=['GET'])
def create_wallet():
    wallet = blockchain.create_wallet()
    response = {'message': 'Wallet created successfully!', 'wallet': wallet}
    return jsonify(response), 200

@app.route('/get_balance/<address>', methods=['GET'])
def get_balance(address):
    balance = blockchain.get_balance(address)
    return jsonify({'address': address, 'balance': balance}), 200

@app.route('/mine_block/<miner_address>', methods=['POST'])
def mine_block(miner_address):
    data = request.get_json()
    range_start = data.get("range_start", 1)
    range_end = data.get("range_end", 1000000)

    last_block = blockchain.chain[-1]
    previous_proof = last_block['proof']
    proof = blockchain.create_proof_of_work(previous_proof, range_start, range_end)
    if proof:
        previous_hash = blockchain.hash(last_block)
        block = blockchain.create_block(proof, previous_hash, miner_address)
        response = {
            'message': 'New block mined successfully!',
            'block': block
        }
    else:
        response = {'message': 'Failed to mine a block in the given range.'}
    return jsonify(response), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
