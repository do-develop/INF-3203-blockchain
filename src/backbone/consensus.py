# backbone/consensus.py
import datetime
import requests 
import sys
sys.path.insert(0,"..")
from abstractions.block import Block, Blockchain
from abstractions.user import User
from utils.flask_utils import flask_call
from utils.cryptographic import *
from requests.packages.urllib3.exceptions import InsecureRequestWarning # type:ignore

# TODO: Implement Proof of Work
# mining algorithm
def mine_block(block:Block, difficulty):
    # example_hash = hash_function(index + prev_hash + timestamp + data + nonce)
    # block.py line 174
    hash = hash_function(block.prev + block.time + block.merkle_root + block.nonce)
    while (hash[:difficulty] is not '0' * difficulty):
        # keep mining
        block.nonce += 1
        hash = hash_function(block.prev + block.time + block.merkle_root + block.nonce)
    block.creation_time = datetime.now().timestamp() - block.time
    return hash

# TODO: Build a block
def build_block(bchain:Blockchain):
    # Create a block
    _, difficulty, _ = flask_call('GET', 'request_difficulty')
    now = datetime.now().timestamp()
    # list of params (hash, nonce, time, creation_time, height)
    new_block = Block('', 0, now, None, bchain.chain.length)
    new_block.hash = mine_block(new_block, difficulty)
    
    # Add the data(header and body) to the block

    # Hash the block

    # Chain the blocks together
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    _, blockchain, code = flask_call('GET', 'get_blockchain')
    if blockchain and code == 200:
        b_chain = Blockchain.load_json(json.dumps(blockchain))
        if b_chain.is_chain_valid():
            b_chain.add_block(new_block)


def resolve_confict():
    '''
    https://github.com/AvinashNath2/Block-Chain-Example/blob/master/Block_Chain.py
    Algorithm to position the block into the longest chain
    '''

def get_my_difficulty():
    my_block = 0
    my_diff = -1
    _, users, code = flask_call('GET', 'get_users')
    if code != 200:
        print("error in flask_call('GET', 'get_user)")
        return
    # get my mined_blocks count
    for user in users:
        u = User.load_json(json.dumps(user))
        if u.username == 'do-develop':
            my_block = u.mined_blocks
    # find my difficulty
    if my_block < 10:
        my_diff = 6
    elif 10 <= my_block < 100:
        my_diff = 7
    elif 100 <= my_block < 200:
        my_diff = 8
    elif 200 <= my_block < 500:
        my_diff = 9
    else:
        my_diff = 10
    return my_diff

if __name__ == "__main__":
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    response, blockchain, code = flask_call('GET', 'get_blockchain')
    b_chain = Blockchain.load_json(json.dumps(blockchain))
    # for b in b_chain.chain:
    #     print(b)
    if b_chain.is_chain_valid():
        print(b_chain.block_list[-1].hash)

 
    


    