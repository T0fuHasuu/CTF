from web3 import Web3

RPC_URL = "RPC_URL"
PRIVKEY = "PRIVATE_KEY"
SETUP_ADDR = Web3.to_checksum_address("SETUP_ADDRESS")

w3 = Web3(Web3.HTTPProvider(RPC_URL))
account = w3.eth.account.from_key(PRIVKEY)
wallet = account.address

setup_abi = [
    {"inputs":[],"name":"nexus","outputs":[{"type":"address"}],"stateMutability":"view","type":"function"},
    {"inputs":[],"name":"essence","outputs":[{"type":"address"}],"stateMutability":"view","type":"function"},
    {"inputs":[],"name":"conductRituals","outputs":[],"stateMutability":"nonpayable","type":"function"},
    {"inputs":[],"name":"isSolved","outputs":[{"type":"bool"}],"stateMutability":"view","type":"function"}
]

essence_abi = [
    {"inputs":[{"type":"address"},{"type":"uint256"}],"name":"approve","outputs":[{"type":"bool"}],"stateMutability":"nonpayable","type":"function"},
    {"inputs":[{"type":"address"},{"type":"uint256"}],"name":"transfer","outputs":[{"type":"bool"}],"stateMutability":"nonpayable","type":"function"},
    {"inputs":[{"type":"address"}],"name":"balanceOf","outputs":[{"type":"uint256"}],"stateMutability":"view","type":"function"}
]

nexus_abi = [
    {"inputs":[{"type":"uint256"}],"name":"attune","outputs":[{"type":"uint256"}],"stateMutability":"nonpayable","type":"function"},
    {"inputs":[{"type":"uint256"},{"type":"address"}],"name":"dissolve","outputs":[{"type":"uint256"}],"stateMutability":"nonpayable","type":"function"}
]

setup = w3.eth.contract(address=SETUP_ADDR, abi=setup_abi)
nexus = w3.eth.contract(address=setup.functions.nexus().call(), abi=nexus_abi)
essence = w3.eth.contract(address=setup.functions.essence().call(), abi=essence_abi)

def send_tx(tx):
    tx["nonce"] = w3.eth.get_transaction_count(wallet)
    tx["gas"] = 3000000
    tx["gasPrice"] = w3.eth.gas_price
    signed = account.sign_transaction(tx)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    return w3.eth.wait_for_transaction_receipt(tx_hash)

max_uint = 2**256 - 1

send_tx(essence.functions.approve(nexus.address, max_uint).build_transaction({"from": wallet}))
send_tx(nexus.functions.attune(1).build_transaction({"from": wallet}))
send_tx(essence.functions.transfer(nexus.address, w3.to_wei(6000, "ether")).build_transaction({"from": wallet}))
send_tx(setup.functions.conductRituals().build_transaction({"from": wallet}))
send_tx(nexus.functions.dissolve(1, wallet).build_transaction({"from": wallet}))

print(setup.functions.isSolved().call())