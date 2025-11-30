#Name: Kamal Lamey  || Nov-30,2025 || 3:29PM
#The following modifications had to be performed:
#Remove unused code
#Added Comments

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
#Kamal modified these keys due to debugging issues
ONTARIO_TECH_PUBLIC_KEY = "30820122300d06092a864886f70d01010105000382010f003082010a02820101008e67a080eade2de2183721b307628a69b0027cfc7e29bc6ad6be484b0eab86777c1f0ecc6ab707a5714eacb980bf485ec771d388294e75f94e642ca89f54a16f4981041e00b2b8631f3850f2668b1256cfa1b70d8ed633bc4ca867c975f3e2a8674c13a27f23e86c3bfbeac2df4ef0343afdbef470fe2ddea0f3b252ac88fd6698f46a029a81afffab97cb4f93da13f7b7949a31f8c576ad104047388f6274c13cffe0c6232e238034e46d247e225897039c9e1722e5c22eaf8610aae874c4ad0c06a70d81678b0d2004bcbfdcbbc3c1a2313c38b326b80ac6362f75ffcda3364b6131d19b9a1b6ee52250086ecd92e480b35b7abf7d4c68f1da671570905c2d0203010001"

# Private Key (hex-encoded DER) for Ontario Tech
# WARNING: In a real deployment this key must NEVER live in the backend code like this.
# I only keep it here to show the full issuer keypair for the course project.
#Kamal modified these keys due to debugging issues
ONTARIO_TECH_PRIVATE_KEY = "308204a402010002820101008e67a080eade2de2183721b307628a69b0027cfc7e29bc6ad6be484b0eab86777c1f0ecc6ab707a5714eacb980bf485ec771d388294e75f94e642ca89f54a16f4981041e00b2b8631f3850f2668b1256cfa1b70d8ed633bc4ca867c975f3e2a8674c13a27f23e86c3bfbeac2df4ef0343afdbef470fe2ddea0f3b252ac88fd6698f46a029a81afffab97cb4f93da13f7b7949a31f8c576ad104047388f6274c13cffe0c6232e238034e46d247e225897039c9e1722e5c22eaf8610aae874c4ad0c06a70d81678b0d2004bcbfdcbbc3c1a2313c38b326b80ac6362f75ffcda3364b6131d19b9a1b6ee52250086ecd92e480b35b7abf7d4c68f1da671570905c2d02030100010282010017cc297e61c18f59614295571dbcd1f4a77d42f5ceff9a85202ddc56eeb4ab5bfc5a145704de6160bc76b156aeb5489ace29af77e9af3af7d6a9d6ecb6f3a5a6bb59dc1e476f9670ba1ee7281b0ad29dbf44ff1a3cec7ee8d0c6b3d16eecbacbf9b734f0cade6d50e915483e18a35070ea0acd867bfb7e1ede36db6e05773f214e475d066131cc140938560a4a9c9ff292835520aba0238470a2b55512fd16bd7e8df24cc4fedb09d7555411f93ff8415c8707bdc51595d0e90e1c31bfab031132b4c8617effedf1590b411d5e08f2d17931ee994d88627b57c7d8b435e9ed036a91eecc077147e9a6d5ea5fd3289114b8194d0296355b455f3dc3bca0565b0102818100b9c1ad292dd66ff2db6da019ec043b61ee54a3cb2f1ca27691475a9ddaea9fc3ab791c149e424532d09128209356ce9f45916750a526e39be6c3a32d3fe3fa230b601999972751ac8c65e7262d894a21c233095ceb1da7c288418292a48dd1d08977f27b7c3229520027156525f016abf935b87b5a6d4ae3156efad2aa247bb902818100c4413f0d73956f6940d27bee64ea5b20dae06a3f206855b201248acf3e6c02be9d0a3533df87d2e11091d594b75343a01d972cf073f17a60b1f7f92e77d5babb9be7edfbe07e60fdadb14bf495ce098e63ef0e815d683ec1ecb962bdfd3ba2b5cd61449eb80f2309a9b6929461e9ea3d2d37948207f05e65a37fbc6d50bae61502818100a6ae62aa3bc65aa7ea3c0158a14eded62e5ce6a8f0ba5a11d8a4d56c263f386304dfe4d19f7cc9c9221bce8d0488f55937bc949f69c26ea4bb3a3b96e3e8b6d07169a72f09d22f588c96f8066afff1743f653a76954703fcebf514ac6f5a0eb678541852b40bf2c5f0fb2118a5253dc2cd196653d1bd9660142084933a370889028181009777d80734bf0ff6c72decb2a8b66bd0e6bd2fa33b0aeba0efdad93b6c6d068d413d00a4e18fbdc530f9ad43135eb321dfd4aebd826ecc49d6f19123391ffef80f3328ed2e6dbbc3ee8b9918d389eabc380ae84215ea800d41fc2ee67d8cca5ed07d92ed811745ae8e8ab784c83136353331e36f9c5afb302cc9488f82304da5028180010bd9d78b6371f7888ed7f64c6ddbd40c366756c6b8eb7a91cd971e7e8c5abd8423f65c5d00e48a03a5d7d032c6d921eaf08c33be5d5f28c883aac674da8917245116bef0ff781f237ee876d3d9d4a2b463031906b0a9cad5988be186eb10b885dce421247ae12335b4fee90e704073f36622b5f1a3c88e072c73010b5c3198"

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
        print("\n🔍 VERIFYING TRANSACTION SIGNATURE")#Kamal added logginf for debugging purposes
        
        if transaction.get('sender') == MINING_SENDER:
            print("✅ Mining transaction - skipping verification")#Kamal added logging for debugging purposes
            return True

        sender_public_key = transaction['sender']
        signature = transaction['signature']

        # ✅ CRITICAL: Reconstruct the ORIGINAL data structure that was signed
        # The client signs: {sender_public_key, recipient_public_key, credential_type, issue_date}
        verification_data = OrderedDict({
            'sender_public_key': transaction['sender'],
            'recipient_public_key': transaction['recipient'],
            'credential_type': transaction['credential_type'],
            'issue_date': transaction['issue_date']
        })
        
        print(f"Verification data: {verification_data}")#Kamal added logging for debugging purposes

        try:
            public_key = RSA.import_key(binascii.unhexlify(sender_public_key))
            verifier = PKCS1_v1_5.new(public_key)
            
            # I use SHA (as in the classic examples) for signing the transaction payload
            h = SHA.new(json.dumps(verification_data, sort_keys=True).encode('utf8'))
            
            result = verifier.verify(h, binascii.unhexlify(signature))
            
			#Adding some code for logging and exception handling
            if result:
                print("✅ SIGNATURE VALID!")
            else:
                print("❌ SIGNATURE INVALID!")
                
            return result
            
        except Exception as e:
            print(f"❌ Signature verification error: {e}")
            import traceback
            traceback.print_exc()
            return False

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

    
    if values.get('sender_public_key') != ONTARIO_TECH_PUBLIC_KEY:
        return jsonify({'message': 'Unauthorized Issuer'}), 401

	#Kamal modified to Check for sender_public_key (not sender)
    required = ['sender_public_key', 'recipient_public_key', 'credential_type', 
                'issue_date', 'credential_hash', 'signature']
    if not all(k in values for k in required):
        return jsonify({'message': 'Missing values'}), 400

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
        return jsonify({'message': str(e)}), 400


#Kamal modified verify_transaction_signature to handle the field names correctly
def verify_transaction_signature(self, transaction):
    """
    This function was developed with the assistance of Claude AI in order to address errors related to data types and formatting
    """
    if transaction.get('sender') == MINING_SENDER:
        return True

    sender_public_key = transaction['sender']
    signature = transaction['signature']
    
    # update mapping against what was ACTUALLY signed by the client
    verification_data = OrderedDict({
        'sender_public_key': transaction['sender'],        # Map back
        'recipient_public_key': transaction['recipient'],  # Map back
        'credential_type': transaction['credential_type'],
        'issue_date': transaction['issue_date']
    })

    # Recreate the public key from the hex-encoded DER representation
    try:
        public_key = RSA.import_key(binascii.unhexlify(sender_public_key))
        verifier = PKCS1_v1_5.new(public_key)
        
        # Use SHA to match what the client used when signing
        h = SHA.new(json.dumps(verification_data, sort_keys=True).encode('utf8'))
        
        # If the verification fails, treat the transaction as invalid
        return verifier.verify(h, binascii.unhexlify(signature))
    except Exception as e:
        print(f"❌ Signature verification error: {e}")
        return False

#View Blockchain comand
@app.route('/blockchain')
def blockchain_page():
    return render_template('blockchain.html')

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

    #Snippet of code to handle name formats being digested
    print(f"\n🔍 VERIFICATION REQUEST")
    print(f"Received keys: {list(values.keys())}")
    
    # Handle both possible field name formats
    recipient_key = values.get('recipient_public_key') or values.get('wallet_address')
    credential_hash = values.get('credential_hash')
    
    print(f"Extracted recipient_key: {recipient_key[:50] if recipient_key else 'None'}...")
    print(f"Extracted credential_hash: {credential_hash}")
    
    if not recipient_key or not credential_hash:
        missing = []
        if not recipient_key:
            missing.append('recipient_public_key or wallet_address')
        if not credential_hash:
            missing.append('credential_hash')
        return jsonify({
            'message': f'Missing values: {", ".join(missing)}'
        }), 400

    print(f"Searching blockchain for:")
    print(f"  Recipient: {recipient_key[:50]}...")
    print(f"  Hash: {credential_hash}")

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
    #parser.add_argument('-p', '--port', default=5000, type=int, help='port to listen on')
    parser.add_argument('-p', '--port', default=5001, type=int, help='port to listen on')
    args = parser.parse_args()
    port = args.port
    app.run(host='127.0.0.1', port=port, debug=True)


