# test_api_endpoints.py
#
# In this test I:
# - Check that the Flask API is reachable
# - Inspect the initial chain and pending transactions
# - Trigger mining via /mine
# - Confirm that a new block was added
#
# NOTE:
# This focuses on testing the HTTP endpoints and mining flow.
# The detailed signature / credential logic is already covered in Test_blockchain.py.

import requests
import json

BASE_URL = "http://127.0.0.1:5000"


def pretty_print(title, data):
    """Small helper so I can see clearly what each request returned."""
    print(f"\n=== {title} ===")
    if isinstance(data, (dict, list)):
        print(json.dumps(data, indent=2))
    else:
        print(data)


def main():
    # 1) Check that /chain is reachable
    r = requests.get(f"{BASE_URL}/chain")
    pretty_print("/chain status code", r.status_code)
    if r.status_code != 200:
        print("❌ Cannot reach /chain. Is the Flask server running on port 5000?")
        return

    chain_before = r.json()
    pretty_print("Chain BEFORE mining", chain_before)

    # 2) Check current pending transactions (unmined)
    r = requests.get(f"{BASE_URL}/transactions/get")
    pretty_print("/transactions/get status code", r.status_code)
    if r.status_code == 200:
        pretty_print("Pending transactions BEFORE mining", r.json())

    # 3) Trigger mining
    r = requests.get(f"{BASE_URL}/mine")
    pretty_print("/mine status code", r.status_code)
    if r.status_code == 200:
        pretty_print("Mine response", r.json())
    else:
        print("❌ /mine failed, cannot continue mining test.")
        return

    # 4) Fetch the chain again to confirm a new block exists
    r = requests.get(f"{BASE_URL}/chain")
    pretty_print("/chain status code (after mining)", r.status_code)
    chain_after = r.json()
    pretty_print("Chain AFTER mining", chain_after)

    # 5) Compare lengths
    before_len = chain_before.get("length", None)
    after_len = chain_after.get("length", None)

    print("\n=== SUMMARY ===")
    print("Length before mining:", before_len)
    print("Length after mining :", after_len)

    if before_len is not None and after_len is not None and after_len == before_len + 1:
        print("✅ Mining endpoint successfully added a new block.")
    else:
        print("⚠ Mining did not behave as expected. Check logs in the Flask terminal.")


if __name__ == "__main__":
    main()
