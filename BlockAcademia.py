from flask import Flask, request, jsonify, render_template
from time import time
from flask_cors import CORS
from collections import OrderedDict
import binascii
import Crypto
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA
from Crypto.Hash import SHA256  # I use SHA-256 to hash credential content securely
from uuid import uuid4
import json
import hashlib
import requests
from urllib.parse import urlparse
import datetime  # I use this to timestamp mining reward transactions

# --- BLOCKACADEMIA CONSTANTS ---
# In this project I hard-code an institutional keypair to represent "Ontario Tech" as the official issuer
# of academic credentials on the blockchain. The public key is used for verification, while the private
# key (in a real system) would stay securely stored on the issuer’s side.

# Public Key (hex-encoded DER) for Ontario Tech
# This key is public and used for verification only.
ONTARIO_TECH_PUBLIC_KEY = "30820122300d06092a864886f70d01010105000382010f003082010a0282010100d8191986c757f59f972b972e0d37651a141b279644f3c7e4663a75868c22262a3928e469d4d80a13d719a79c5c99d255743b0d4957e841280f555d4956e10f1350a455a43292451f50a8677c3e12151676609930c79321c82824701258d462612a439268615c0e42d76378c52089408018e6e5f80b2f566e133c94297123efd625ff115682885971a8141441865c363f59e7f833333331b2c451a941a31969446d3e75a646c243883a45c3639145695287e0766437d04e3047d2f95b8716760662d08a531e285a86481232845c48b0a944607730e2003c2670e303f56b3b27b40974917ccf033008447d488950f2203e3090203010001"

# Private Key (hex-encoded DER) for Ontario Tech
# WARNING: In a real deployment this key must NEVER live in the backend code like this.
# I only keep it here to show the full issuer keypair for the course project.
ONTARIO_TECH_PRIVATE_KEY = "30820464020100300d06092a864886f70d01010105000482044e3082044a0201000282010100d8191986c757f59f972b972e0d37651a141b279644f3c7e4663a75868c22262a3928e469d4d80a13d719a79c5c99d255743b0d4957e841280f555d4956e10f1350a455a43292451f50a8677c3e12151676609930c79321c82824701258d462612a439268615c0e42d76378c52089408018e6e5f80b2f566e133c94297123efd625ff115682885971a8141441865c363f59e7f833333331b2c451a941a31969446d3e75a646c243883a45c3639145695287e0766437d04e3047d2f95b8716760662d08a531e285a86481232845c48b0a944607730e2003c2670e303f56b3b27b40974917ccf033008447d488950f2203e309020301000102820100234a415b228643190823c316279f5383a15291b53f66c2560a80e461a347321288c1c9118c728080f3319800742183c50974b6200af3a681c640e7d584992982d689b65e900a6e4d580f4f727c95e1c8d55a9019685a73a1198f1262d0a0d5402030c6b165243160a006c683b5d233c7f938d0c007c57f6b0f023769c37564cc833075c2e17e47a9609a34103135c398e09f584e037803e7f6e80b271d9992f155949d273a55787321115160086395b8d2d46e9275825000282010091764c0678f13b63cc9164b3838618e4708ff5734e56920f1883394639458f29d20c326074220359f13110900e5728a3f5a7a13d1af14421b83d1c92f16d99763717e3371901a0862088f72a4c1ff0656a81d4a0f4435cc9ff216f49774643034293f92d40973e21528641a9425143a3d537f9037048ff4b98ef1f22e702818100e4b78917e383437e693120155b9e84b840808b8b3a77f3743c3f91547844f22718e244ed954848074983050074704b281f6d3383a213454641620c355af553f191599818815180630b7762699e31d054d436a536966606102146e2f1712a84d43be982302818100c87a1d1326461afb8451c243886af34812a0f8b8a531f82b9a7c640e104192b429d2f232b7190f89d3115456f4d2217c992705b6510e8d0e2e920d3f66a2133f6797b5e43a9f4c33e214f4e2f80c55f560e7b8a7f14b301a012a4b86e0c60959242d99d19a4e2197171d798a3c5a755d9d7f5733857b28292c019902818100ba03e877e5d89487c53d0d8295a0cc25ef84b0fa28889980d0d87a41921c5f35d5568582d96924b81b8040a3311f93f5383e20e8b15a6b5791a8e108c90858102a061c0e353597d643886f7535b48ff007b8b4887326847af6c44933a089901570530b13480824b232677467332c1c68615b6d54751f0b027027302818037389a3f2b1d61c16223595f9227c8d9e2b10a26d7f02235559d7d3d1be6415f341490915f013d2891157c70e3f05531d0a5b28d68f2fa41f2371285038c62c2f21136e053f3e61823126be151240188995383d47c20c092670e30129215089c7d81a9657b01932759e0a294878b1758c56e3002818100a94d0364e7c72477f1012920f04f464082269a8b1392e2762a4d0484e5141ff23b24f576e031e4e3e3b0921a8d011c7c97561f50a8b137f818d1a1b80360a0b271a3962d3122c60e36338b77a7f6f59837968a3350117498c48a7374026615b223d6a690e531818d601d3b5b6378e9f50e7a17387f34c2049d1159670d"

CREDENTIAL_ISSUER_ID = "Ontario Tech"

# Special constants for mining behaviour
MINING_SENDER = "The Blockchain"  # I use this logical sender to represent system-generated mining rewards
MINING_REWARD = 1                 # Fixed reward (in “credits”) per mined block
MINING_DIFFICULTY = 2             # Number of leading zeros required in the PoW hash


class Blockchain:
    """
    In this class I implement the core blockchain logic for BlockAcademia.
    - I maintain a chain of blocks storing credential transactions.
    - I implement Proof of Work for basic Sybil resistance.
    - I verify digital signatures so that only Ontario Tech can issue credentials.
    """

    def __init__(self):
        """
        When I initialize the blockchain:
        - I start with an empty list of pending transactions.
        - I create an empty list for the chain itself.
        - I track known peer nodes in a set.
        - I assign a unique node_id so this backend can be identified as a miner.
        - Finally, I create a genesis block (block 1) with a fixed previous hash.
        """
        self.transactions = []
        self.chain = []
        self.nodes = set()
        self.node_id = str(uuid4()).replace('-', '')
        # Create the genesis block
        self.create_block(0, '00')

    def register_node(self, node_url):
        """
        Here I register a new peer node (another BlockAcademia backend) by its URL.
        This is used later when I try to reach network consensus and resolve conflicts.
        """
        parsed_url = urlparse(node_url)
        if parsed_url.netloc:
            self.nodes.add(parsed_url.netloc)
        elif parsed_url.path:
            self.nodes.add(parsed_url.path)
        else:
            raise ValueError('Invalid URL')

    def create_block(self, nonce, previous_hash):
        """
        Once Proof of Work is solved, I call this helper to actually append
        a new block to the chain.

        :param nonce: The nonce that satisfied the difficulty target.
        :param previous_hash: The SHA-256 hash of the previous block.
        :return: The newly created block.
        """
        block = {
            'block_number': len(self.chain) + 1,
            'timestamp': time(),
            'transactions': self.transactions,  # all pending (validated) transactions
            'nonce': nonce,
            'previous_hash': previous_hash
        }

        # After I pack the transactions into a block, I clear the pending list
        self.transactions = []
        self.chain.append(block)
        return block

    def hash(self, block):
        """
        I use this helper to compute a SHA-256 hash of a block.
        I make sure to sort the keys so the hash is deterministic.

        :param block: <dict> Block to be hashed.
        :return: <str> Hex-encoded SHA-256 hash of the block.
        """
        block_string = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    def new_transaction(self, sender, recipient, credential_type, issue_date,
                        credential_hash, signature):
        """
        This method is my entry point to add a *validated* transaction to the list of
        pending transactions before mining.

        In my use case, a transaction represents an academic credential being issued.

        :param sender: Issuer's public key (hex-encoded DER). For real credentials, this
                       must be the Ontario Tech public key.
        :param recipient: Student's public key (hex-encoded DER).
        :param credential_type: e.g., "MITS AI", "B.Sc. Computer Science".
        :param issue_date: Human-readable issue date string.
        :param credential_hash: SHA-256 hash of the full credential data.
        :param signature: Digital signature of the transaction payload (hex-encoded).
        :return: Index of the block that will contain this transaction.
        """
        transaction = OrderedDict({
            'sender': sender,
            'recipient': recipient,
            'credential_type': credential_type,
            'issue_date': issue_date,
            'credential_hash': credential_hash,
            'signature': signature
        })

        # Special-case: mining rewards are system-generated and do not carry a real
        # RSA signature. I allow those as long as the sender is my MINING_SENDER.
        if sender == MINING_SENDER:
            self.transactions.append(transaction)
            return self.last_block['block_number'] + 1

        # For real credential transactions, I verify the digital signature first.
        if self.verify_transaction_signature(transaction):
            self.transactions.append(transaction)
            return self.last_block['block_number'] + 1
        else:
            # I explicitly reject tampered or incorrectly signed credentials at this point.
            raise ValueError('Invalid transaction signature. Credential rejected.')

    def verify_transaction_signature(self, transaction):
        """
        Here I verify the RSA digital signature attached to a transaction.

        - I remove the 'signature' field before hashing the payload.
        - I reconstruct the RSA public key from the hex-encoded DER.
        - I verify that the provided signature matches the hashed payload.

        :param transaction: OrderedDict with at least sender and signature fields.
        :return: True if the signature is valid (or the tx is a mining reward), False otherwise.
        """
        # I intentionally skip signature verification for mining-reward transactions.
        # Those are “system” transactions created by the protocol itself.
        if transaction.get('sender') == MINING_SENDER:
            return True

        sender_public_key = transaction['sender']
        signature = transaction['signature']

        # I copy the transaction and remove the signature field so it is not part of the hash.
        verification_data = transaction.copy()
        del verification_data['signature']

        # Recreate the public key from the hex-encoded DER representation
        public_key = RSA.importKey(binascii.unhexlify(sender_public_key))
        verifier = PKCS1_v1_5.new(public_key)

        # I use SHA (as in the classic examples) for signing the transaction payload
        h = SHA.new(json.dumps(verification_data, sort_keys=True).encode('utf8'))

        # If the verification fails, I treat the transaction as invalid
        return verifier.verify(h, binascii.unhexlify(signature))

    @property
    def last_block(self):
        """
        Convenience property so I can easily access the most recent block.
        """
        return self.chain[-1]

    def proof_of_work(self, last_block):
        """
        In this method I implement a basic Proof of Work mechanism.

        - I take the hash of the previous block.
        - I iterate over nonces until I find one that yields a hash with
          MINING_DIFFICULTY leading zeros.

        :param last_block: The previous block in the chain.
        :return: A valid nonce that satisfies the difficulty target.
        """
        last_hash = self.hash(last_block)
        nonce = 0

        # I iterate until I find a nonce that satisfies valid_proof()
        while self.valid_proof(self.transactions, last_hash, nonce) is False:
            nonce += 1

        return nonce

    def valid_proof(self, transactions, last_hash, nonce, difficulty=MINING_DIFFICULTY):
        """
        Here I define the actual PoW puzzle.

        - I hash together the list of transactions waiting to be included,
          the previous block hash, and the nonce.
        - If the resulting hash starts with the required number of zeros,
          the proof is considered valid.

        :param transactions: List of transactions the miner is including.
        :param last_hash: Hash of the previous block.
        :param nonce: Candidate nonce.
        :param difficulty: Number of leading zeros required.
        :return: True if the guessed hash satisfies the difficulty, False otherwise.
        """
        guess = (str(transactions) + str(last_hash) + str(nonce)).encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        return guess_hash[:difficulty] == '0' * difficulty

    def valid_chain(self, chain):
        """
        In this method I fully re-validate a candidate blockchain.

        For every block after the genesis block I check:
        1. The previous_hash field actually matches the hash of the previous block.
        2. The Proof of Work is valid for the full set of transactions in that block.
        3. Every credential transaction carries a valid signature (mining reward is exempt).

        :param chain: A complete candidate chain (list of blocks).
        :return: True if the chain is internally consistent and valid, False otherwise.
        """
        if not chain:
            return False

        last_block = chain[0]
        current_index = 1

        while current_index < len(chain):
            block = chain[current_index]

            # 1) Check that this block is correctly chained to the previous one
            if block['previous_hash'] != self.hash(last_block):
                return False

            transactions = block['transactions']

            # 2) Check that the proof of work is still valid for this block’s contents.
            #    NOTE: here I deliberately use *all* transactions in the block. In my design,
            #    the mining reward is already part of the list when PoW is computed.
            if not self.valid_proof(transactions, block['previous_hash'], block['nonce']):
                return False

            # 3) Check signatures for all credential transactions on this block.
            for tx in transactions:
                if tx.get('sender') != MINING_SENDER:
                    if not self.verify_transaction_signature(tx):
                        return False

            last_block = block
            current_index += 1

        return True

    def resolve_conflicts(self):
        """
        This is my simple network consensus algorithm based on "longest valid chain wins".

        - I fetch the /chain endpoint from all known peer nodes.
        - I accept the longest chain *only if* it passes my valid_chain checks.
        - If I replace my local chain, I return True so the caller knows an update happened.
        """
        neighbours = self.nodes
        new_chain = None

        # I only care about chains longer than my current one
        max_length = len(self.chain)

        # Pull chains from each neighbour and validate them
        for node in neighbours:
            response = requests.get(f'http://{node}/chain')

            if response.status_code == 200:
                length = response.json()['length']
                chain = response.json()['chain']

                # I only switch to a longer and fully valid chain
                if length > max_length and self.valid_chain(chain):
                    max_length = length
                    new_chain = chain

        # If I find a better chain, I adopt it
        if new_chain:
            self.chain = new_chain
            return True

        return False


# --- FLASK APP INITIALIZATION ---
# I expose the blockchain functionality through a small Flask API so my React/HTML UI can
# talk to it over HTTP.

app = Flask(__name__)
CORS(app)
blockchain = Blockchain()


# --- API ROUTES ---

@app.route('/mine', methods=['GET'])
def mine():
    """
    Mining endpoint:
    - I run Proof of Work on the pending transactions.
    - I create a special mining reward transaction paid to this node.
    - I forge a new block and append it to the chain.
    """
    last_block = blockchain.last_block
    nonce = blockchain.proof_of_work(last_block)

    # I reward the miner (this node) for doing the work.
    # This is a system transaction, so I use MINING_SENDER and a dummy "signature".
    blockchain.new_transaction(
        sender=MINING_SENDER,
        recipient=blockchain.node_id,
        credential_type="MINING_REWARD",
        issue_date=str(datetime.date.today()),
        credential_hash="REWARD_HASH",
        signature="0"  # Not a real signature; handled specially in new_transaction/verification
    )

    # Forge the new block by adding it to the chain
    previous_hash = blockchain.hash(last_block)
    block = blockchain.create_block(nonce, previous_hash)

    response = {
        'message': 'New Block Forged',
        'block_number': block['block_number'],
        'transactions': block['transactions'],
        'nonce': block['nonce'],
        'previous_hash': block['previous_hash'],
    }
    return jsonify(response), 200


@app.route('/credentials/new', methods=['POST'])
def new_credential():
    """
    This route is called by the UI when Ontario Tech issues a new credential.

    - I expect the issuer to be the Ontario Tech public key.
    - I validate all required fields.
    - I pass the transaction to the blockchain, which verifies the signature again.
    """
    values = request.get_json()

    # Security gate: in my model only Ontario Tech is allowed to issue credentials.
    if values.get('sender_public_key') != ONTARIO_TECH_PUBLIC_KEY:
        return jsonify({'message': 'Unauthorized Issuer'}), 401

    required = ['recipient_public_key', 'credential_type', 'issue_date', 'credential_hash', 'signature']
    if not all(k in values for k in required):
        return 'Missing values', 400

    try:
        # I create a new credential transaction that will be mined into the next block.
        index = blockchain.new_transaction(
            sender=values['sender_public_key'],
            recipient=values['recipient_public_key'],
            credential_type=values['credential_type'],
            issue_date=values['issue_date'],
            credential_hash=values['credential_hash'],
            signature=values['signature']
        )
        response = {'message': f'Credential will be added to Block {index}'}
        return jsonify(response), 201

    except ValueError as e:
        # Any signature or validation failure is surfaced to the client here.
        return jsonify({'message': str(e)}), 400


@app.route('/credentials/verify', methods=['POST'])
def verify_credential():
    """
    This endpoint lets a verifier (e.g., an employer) confirm that a credential exists
    on the chain and that it was truly issued by Ontario Tech.

    - I search the blockchain for a matching recipient_public_key + credential_hash pair.
    - I confirm that the sender is the official issuer.
    - I re-verify the digital signature on the stored transaction.
    """
    values = request.get_json()
    required = ['recipient_public_key', 'credential_hash']
    if not all(k in values for k in required):
        return jsonify({'message': 'Missing values (recipient_public_key, credential_hash)'}), 400

    recipient_key = values['recipient_public_key']
    credential_hash = values['credential_hash']

    # I scan every block and transaction for a matching credential.
    for block in blockchain.chain:
        for transaction in block['transactions']:
            if (
                transaction.get('recipient') == recipient_key
                and transaction.get('credential_hash') == credential_hash
            ):
                # Check 1: ensure the sender is the trusted issuer
                if transaction.get('sender') != ONTARIO_TECH_PUBLIC_KEY:
                    return jsonify({
                        'is_valid': False,
                        'message': 'Credential found, but the issuer is not trusted (not Ontario Tech).'
                    }), 200

                # Check 2: verify the digital signature on the transaction
                if blockchain.verify_transaction_signature(transaction):
                    response = {
                        'is_valid': True,
                        'message': 'Credential found and verified on the blockchain!',
                        'issuer': CREDENTIAL_ISSUER_ID,
                        'credential_type': transaction.get('credential_type'),
                        'issue_date': transaction.get('issue_date'),
                        'recipient': recipient_key,
                        # I also expose a stable transaction_id (hash of the transaction record).
                        'transaction_id': hashlib.sha256(
                            json.dumps(transaction, sort_keys=True).encode()
                        ).hexdigest()
                    }
                    return jsonify(response), 200
                else:
                    return jsonify({
                        'is_valid': False,
                        'message': 'Credential found, but the digital signature verification failed. '
                                   'The data may have been tampered with.'
                    }), 200

    # If I finish scanning and find nothing, I treat the credential as not recorded on-chain
    return jsonify({
        'is_valid': False,
        'message': 'Credential not found on the public blockchain.'
    }), 200


@app.route('/chain', methods=['GET'])
def full_chain():
    """
    Helper route to expose the full chain.
    I use this for debugging, for consensus with peers, and for visualization in the UI.
    """
    response = {
        'chain': blockchain.chain,
        'length': len(blockchain.chain),
    }
    return jsonify(response), 200


@app.route('/transactions/get', methods=['GET'])
def get_transactions():
    """
    This route lets me inspect the current list of pending (unmined) transactions.
    """
    transactions = blockchain.transactions
    response = {'transactions': transactions}
    return jsonify(response), 200


@app.route('/nodes/get', methods=['GET'])
def get_nodes():
    """
    I expose the list of known peer nodes here for transparency and debugging.
    """
    nodes = list(blockchain.nodes)
    response = {'nodes': nodes}
    return jsonify(response), 200


@app.route('/nodes/resolve', methods=['GET'])
def consensus():
    """
    When I hit this endpoint, the node runs resolve_conflicts() and possibly
    replaces its chain with a longer valid one from the network.
    """
    replaced = blockchain.resolve_conflicts()

    if replaced:
        response = {
            'message': 'Our chain was replaced',
            'new_chain': blockchain.chain
        }
    else:
        response = {
            'message': 'Our chain is authoritative',
            'chain': blockchain.chain
        }
    return jsonify(response), 200


@app.route('/nodes/register', methods=['POST'])
def register_node():
    """
    This POST endpoint lets me register multiple new peer nodes at once.
    The UI sends a comma-separated list like: "127.0.0.1:5002,127.0.0.1:5003".
    """
    values = request.form
    # Example: 127.0.0.1:5002,127.0.0.1:5003,127.0.0.1:5004
    nodes = values.get('nodes').replace(' ', '').split(',')

    if nodes is None:
        return 'Error: Please supply a valid list of nodes', 400

    for node in nodes:
        blockchain.register_node(node)

    response = {
        'message': 'Nodes have been added',
        'total_nodes': [node for node in blockchain.nodes]
    }
    return jsonify(response), 201


if __name__ == '__main__':
    # I let the app listen on a configurable port so I can run multiple nodes locally.
    from argparse import ArgumentParser
    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=5000, type=int, help='port to listen on')
    args = parser.parse_args()
    port = args.port
    app.run(host='127.0.0.1', port=port, debug=True)


