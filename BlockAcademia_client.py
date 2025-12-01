#Name: Kamal Lamey  || Nov-30,2025 || 3:29PM
#The following modifications had to be performed:
#Remove unused code
#Added Comments

from flask import Flask, render_template, request, jsonify
import Crypto
import Crypto.Random
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA, SHA256
import binascii
import binascii
from Crypto.PublicKey import RSA
from collections import OrderedDict
import json
import datetime
from datetime import date
import requests
import os

""" Please note that this client python script was developed with the Assistance of Gemini AI model using the repositories shared during class excerise for weeks 3-5 (https://pastebin.com/2f70amw1, https://pastebin.com/2f70amw1, https://pastebin.com/EtzJ8pFk and https://pastebin.com/EpK3xcMK); where the prompts used are as follows:
 1. "I need to build a new web app to interface with the web for my project given the following files. I have an existing file can you refactor so that it simulates the results in the test cases" (files included in this prompt were the files from the URLs mentioned above in addition to the Blockchain Project.zip file and Stella's BlockChain class (BlockAcademia.py) as well as the test cases included (Test_blockchain.py and Test_api_endpoints.py)) """

# Public Key (hex-encoded DER) for Ontario Tech
# This key is public and used for verification only.
#Updated keys from the BlockAcademia Backend file
ONTARIO_TECH_PUBLIC_KEY = "30820122300d06092a864886f70d01010105000382010f003082010a02820101008e67a080eade2de2183721b307628a69b0027cfc7e29bc6ad6be484b0eab86777c1f0ecc6ab707a5714eacb980bf485ec771d388294e75f94e642ca89f54a16f4981041e00b2b8631f3850f2668b1256cfa1b70d8ed633bc4ca867c975f3e2a8674c13a27f23e86c3bfbeac2df4ef0343afdbef470fe2ddea0f3b252ac88fd6698f46a029a81afffab97cb4f93da13f7b7949a31f8c576ad104047388f6274c13cffe0c6232e238034e46d247e225897039c9e1722e5c22eaf8610aae874c4ad0c06a70d81678b0d2004bcbfdcbbc3c1a2313c38b326b80ac6362f75ffcda3364b6131d19b9a1b6ee52250086ecd92e480b35b7abf7d4c68f1da671570905c2d0203010001"

# Private Key (hex-encoded DER) for Ontario Tech
# WARNING: In a real deployment this key must NEVER live in the backend code like this.
# I only keep it here to show the full issuer keypair for the course project.
#Updated keys from the BlockAcademia Backend file
ONTARIO_TECH_PRIVATE_KEY = "308204a402010002820101008e67a080eade2de2183721b307628a69b0027cfc7e29bc6ad6be484b0eab86777c1f0ecc6ab707a5714eacb980bf485ec771d388294e75f94e642ca89f54a16f4981041e00b2b8631f3850f2668b1256cfa1b70d8ed633bc4ca867c975f3e2a8674c13a27f23e86c3bfbeac2df4ef0343afdbef470fe2ddea0f3b252ac88fd6698f46a029a81afffab97cb4f93da13f7b7949a31f8c576ad104047388f6274c13cffe0c6232e238034e46d247e225897039c9e1722e5c22eaf8610aae874c4ad0c06a70d81678b0d2004bcbfdcbbc3c1a2313c38b326b80ac6362f75ffcda3364b6131d19b9a1b6ee52250086ecd92e480b35b7abf7d4c68f1da671570905c2d02030100010282010017cc297e61c18f59614295571dbcd1f4a77d42f5ceff9a85202ddc56eeb4ab5bfc5a145704de6160bc76b156aeb5489ace29af77e9af3af7d6a9d6ecb6f3a5a6bb59dc1e476f9670ba1ee7281b0ad29dbf44ff1a3cec7ee8d0c6b3d16eecbacbf9b734f0cade6d50e915483e18a35070ea0acd867bfb7e1ede36db6e05773f214e475d066131cc140938560a4a9c9ff292835520aba0238470a2b55512fd16bd7e8df24cc4fedb09d7555411f93ff8415c8707bdc51595d0e90e1c31bfab031132b4c8617effedf1590b411d5e08f2d17931ee994d88627b57c7d8b435e9ed036a91eecc077147e9a6d5ea5fd3289114b8194d0296355b455f3dc3bca0565b0102818100b9c1ad292dd66ff2db6da019ec043b61ee54a3cb2f1ca27691475a9ddaea9fc3ab791c149e424532d09128209356ce9f45916750a526e39be6c3a32d3fe3fa230b601999972751ac8c65e7262d894a21c233095ceb1da7c288418292a48dd1d08977f27b7c3229520027156525f016abf935b87b5a6d4ae3156efad2aa247bb902818100c4413f0d73956f6940d27bee64ea5b20dae06a3f206855b201248acf3e6c02be9d0a3533df87d2e11091d594b75343a01d972cf073f17a60b1f7f92e77d5babb9be7edfbe07e60fdadb14bf495ce098e63ef0e815d683ec1ecb962bdfd3ba2b5cd61449eb80f2309a9b6929461e9ea3d2d37948207f05e65a37fbc6d50bae61502818100a6ae62aa3bc65aa7ea3c0158a14eded62e5ce6a8f0ba5a11d8a4d56c263f386304dfe4d19f7cc9c9221bce8d0488f55937bc949f69c26ea4bb3a3b96e3e8b6d07169a72f09d22f588c96f8066afff1743f653a76954703fcebf514ac6f5a0eb678541852b40bf2c5f0fb2118a5253dc2cd196653d1bd9660142084933a370889028181009777d80734bf0ff6c72decb2a8b66bd0e6bd2fa33b0aeba0efdad93b6c6d068d413d00a4e18fbdc530f9ad43135eb321dfd4aebd826ecc49d6f19123391ffef80f3328ed2e6dbbc3ee8b9918d389eabc380ae84215ea800d41fc2ee67d8cca5ed07d92ed811745ae8e8ab784c83136353331e36f9c5afb302cc9488f82304da5028180010bd9d78b6371f7888ed7f64c6ddbd40c366756c6b8eb7a91cd971e7e8c5abd8423f65c5d00e48a03a5d7d032c6d921eaf08c33be5d5f28c883aac674da8917245116bef0ff781f237ee876d3d9d4a2b463031906b0a9cad5988be186eb10b885dce421247ae12335b4fee90e704073f36622b5f1a3c88e072c73010b5c3198"

# --- FLASK SETUP ---
app = Flask(__name__)
CONNECTED_NODE_ADDRESS = "http://127.0.0.1:5001"  # central node (This is where BlockChain backend is running)
# This client runs on port 5000 by default.

# --- UTILITY CLASS: Credential ---
class Credential:
    """Represents the data structure for a credential to be signed and hashed."""
    def __init__(self, sender_public_key, recipient_public_key, credential_type, issue_date):
        self.sender_public_key = sender_public_key
        self.recipient_public_key = recipient_public_key
        self.credential_type = credential_type
        self.issue_date = issue_date

    def to_dict(self):
        return OrderedDict({
            'sender_public_key': self.sender_public_key,
            'recipient_public_key': self.recipient_public_key,
            'credential_type': self.credential_type,
            'issue_date': self.issue_date
        })

    def get_credential_hash(self):
        data_string = json.dumps(self.to_dict(), sort_keys=True).encode('utf8')
        return SHA256.new(data_string).hexdigest()

    """ Method used to sign the transaction to provide immuitability from the issuer/Institution proving authenticity of the academic credential issued """
    def sign_transaction(self, private_key_hex):
        try:
            # Clean the hex string (remove any whitespace)
            clean_hex = private_key_hex.strip().replace('\n', '').replace('\r', '').replace(' ', '')
            
            # Convert hex to bytes
            private_key_bytes = binascii.unhexlify(clean_hex)
            
            # Import the RSA key from DER format
            private_key = RSA.import_key(private_key_bytes)

            # Create signer
            signer = PKCS1_v1_5.new(private_key)
            
            # Hash the transaction data (must match what backend expects)
            h = SHA.new(json.dumps(self.to_dict(), sort_keys=True).encode('utf8'))
            
            # Sign and return hex-encoded signature
            signature = signer.sign(h)
            return binascii.hexlify(signature).decode('ascii')
        
        #Error handling generated by Gemini AI
        except (ValueError, TypeError, binascii.Error) as e:
            print(f"❌ Detailed signing error: {type(e).__name__}: {e}")
            print(f"Private key length: {len(private_key_hex)}")
            print(f"First 50 chars: {private_key_hex[:50]}")
            raise ValueError(f"Invalid private key format: {e}")

# --- CLIENT ROUTES (Renders HTML Pages) ---

#Custom BlockAcademia Home Page (index)
@app.route('/')
def index():
    return render_template('index.html')

#View Blockchain command. This will bring up the custom javascript which integrates with the Backend to show BlockChain Data
@app.route('/blockchain')
def blockchain_page():
    return render_template('blockchain.html')

#Issue Credential API. This will bring up the custom javascript which integrates with the Backend and client to issue Credential certificate information
@app.route('/issue/credential')
def issue_credential_page():
    return render_template('credential_Issue.html',
                           issuer_private_key=ONTARIO_TECH_PRIVATE_KEY,
                           issuer_public_key=ONTARIO_TECH_PUBLIC_KEY,
                           today=date.today().isoformat())

#Verify Credential API. This will bring up the custom javascript which integrates with the Backend and client to issue Credential certificate information
@app.route('/verify/credential')
def verify_credential_page():
    return render_template('credentialVerification.html')

""" @app.route('/configure')
def configure_node_page():
    return render_template('configure.html') """


# --- API ENDPOINTS (Client-side Logic) ---
#Function used as an intermediary between the web interface (frontend) and the blockchain to implement the credential issuing process, where Issue Academic Credential from the Issuer Back End [in our Example OntarioTech] which will use the requestors public key to issue their credential which will be signed by the Instituitions private key and the resulting signature and hash will be provided to the requestor for use for future verification. Once issued the function will send the credential to the blockchain to be mined in the future.
#Data Flows as follows: Frontend → This API Endpoint → Blockchain Node → Transaction Pool → Blockchain

@app.route('/api/issue/credential', methods=['POST'])
def issue_credential_api():
    """Handles credential issuance: hashing, signing, and sending to the central node."""
    data = request.get_json()

    #Check that all five required fields are present in the JSON request body, if not a failure will be raised
    required = ['sender_public_key', 'sender_private_key', 'recipient_public_key', 'credential_type', 'issue_date']
    if not all(k in data for k in required):
        return jsonify({'message': 'Missing fields in JSON payload'}), 400

    #Extracts data previously validated above
    sender_public_key = data['sender_public_key']
    sender_private_key = data['sender_private_key']
    recipient_public_key = data['recipient_public_key']
    credential_type = data['credential_type']
    issue_date = data['issue_date']

    # Debug Logging generated by Gemini AI
    print(f"📝 Issuing credential:")
    print(f"   Sender public key length: {len(sender_public_key)}")
    print(f"   Sender private key length: {len(sender_private_key)}")
    print(f"   Recipient public key length: {len(recipient_public_key)}")
    print(f"   Credential type: {credential_type}")
    print(f"   Issue date: {issue_date}")

    credential = Credential(sender_public_key, recipient_public_key, credential_type, issue_date)
    credential_hash = credential.get_credential_hash()

    print(f"   Credential hash: {credential_hash}")

    #Attempt to sign the Credential to be issued
    try:
        signature = credential.sign_transaction(sender_private_key)
        print(f"   ✅ Signature generated: {signature[:50]}...")
    except Exception as e:
        print(f"   ❌ Signing failed: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'message': f'Error signing transaction: {str(e)}'}), 500

    # ✅ Match backend expectations (sender, recipient, not sender_public_key, recipient_public_key)
    payload = {
        'sender_public_key': sender_public_key,
        'recipient_public_key': recipient_public_key,
        'credential_type': credential_type,
        'issue_date': issue_date,
        'credential_hash': credential_hash,
        'signature': signature
    }

    print(f"📤 Sending to blockchain node: {CONNECTED_NODE_ADDRESS}/credentials/new")

    try:
        response = requests.post(f'{CONNECTED_NODE_ADDRESS}/credentials/new', json=payload)#Posting information to the BlockChain
        print(f"📥 Response status: {response.status_code}")
        print(f"📥 Response body: {response.text}")

        #Success Condition
        if response.status_code == 201:
            return jsonify({
                'message': 'Credential issued and added to transaction pool.',
                'credential_data': payload,
                'signature': signature
            }), 200
        #Error Handling
        else:
            try:
                error_message = response.json().get("message", "Unknown error from blockchain node.")
            except json.JSONDecodeError:
                error_message = response.text

            return jsonify({
                'message': f'Failed to issue credential: {error_message}',
                'status_code': response.status_code
            }), response.status_code
            
    #Handle Network related Issues
    except requests.exceptions.RequestException as e:
        print(f"❌ Request failed: {e}")
        return jsonify({'message': f'Failed to connect to blockchain node: {str(e)}'}), 500

#Function used to generate fresh RSA public/private keys to requester in hexadecimal format. These keys will be used to Issue a unique certificate on the blockchain that the user will verify later with a hash.
@app.route('/wallet/new')
def new_wallet():
    random_gen = Crypto.Random.new().read
    private_key = RSA.generate(2048, random_gen) 
    public_key = private_key.publickey()
    
    response = {
        'private_key': binascii.hexlify(private_key.exportKey(format='DER')).decode('ascii'),
        'public_key': binascii.hexlify(public_key.exportKey(format='DER')).decode('ascii')
    }
    return jsonify(response), 200


# --- MAIN EXECUTION ---
if __name__ == '__main__':
    from argparse import ArgumentParser
    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=5000, type=int, help='port to listen on')
    args = parser.parse_args()
    port = args.port
    app.run(host='0.0.0.0', port=port, debug=True)
