# Test_blockchain.py
#
# In this test I:
# - Create a fresh Blockchain instance
# - Generate a temporary issuer keypair (acts like Ontario Tech for testing)
# - Generate a temporary student keypair
# - Issue one credential transaction
# - Mine a block that includes it
# - Validate the chain

from BlockAcademia import Blockchain
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA, SHA256
import binascii
import json


def sign_credential_payload(private_key_obj, payload_dict):
    """
    Here I sign the credential payload using the issuer's private key.
    This matches how the backend verifies signatures (SHA + PKCS1_v1_5).
    """
    signer = PKCS1_v1_5.new(private_key_obj)
    h = SHA.new(json.dumps(payload_dict, sort_keys=True).encode("utf8"))
    signature = signer.sign(h)
    return binascii.hexlify(signature).decode()


def main():
    # 1) I create a fresh blockchain instance
    bc = Blockchain()
    print("Genesis block number:", bc.last_block["block_number"])

    # 2) I generate a temporary issuer keypair (for this test only)
    issuer_key = RSA.generate(2048)
    issuer_public_hex = binascii.hexlify(
        issuer_key.publickey().export_key(format="DER")
    ).decode()

    # 3) I generate a temporary student keypair
    student_key = RSA.generate(2048)
    student_public_hex = binascii.hexlify(
        student_key.publickey().export_key(format="DER")
    ).decode()

    # 4) I build a dummy credential payload
    credential_data = {
        "student_name": "Test Student",
        "program": "MITS AI",
        "degree": "Masters",
        "grad_year": 2025,
    }

    # This is what I store as credential_hash on-chain
    credential_hash = SHA256.new(
        json.dumps(credential_data, sort_keys=True).encode()
    ).hexdigest()

    # 5) I create the transaction payload (without signature)
    tx_payload = {
        "sender": issuer_public_hex,
        "recipient": student_public_hex,
        "credential_type": "MITS AI",
        "issue_date": "28/11/2025",
        "credential_hash": credential_hash,
    }

    # 6) I sign the payload using the issuer's private key
    signature_hex = sign_credential_payload(issuer_key, tx_payload)
    tx_payload["signature"] = signature_hex

    # 7) I add the signed transaction to the blockchain
    index = bc.new_transaction(
        sender=tx_payload["sender"],
        recipient=tx_payload["recipient"],
        credential_type=tx_payload["credential_type"],
        issue_date=tx_payload["issue_date"],
        credential_hash=tx_payload["credential_hash"],
        signature=tx_payload["signature"],
    )
    print("Credential will be included in block:", index)

    # 8) I mine a new block so the transaction is actually written on-chain
    nonce = bc.proof_of_work(bc.last_block)
    new_block = bc.create_block(nonce, bc.hash(bc.chain[-1]))
    print("Mined block number:", new_block["block_number"])
    print("Block transactions:", new_block["transactions"])

    # 9) As a final step, I verify that the full chain is still valid
    print("Chain valid?", bc.valid_chain(bc.chain))


if __name__ == "__main__":
    main()
