# backbone/consensus.py
import time, sys, os, rsa
import requests
from typing import List
from datetime import datetime

sys.path.insert(0,"..")
from backbone.merkle import MerkleTree
from abstractions.block import Block, Blockchain
from abstractions.transaction import Transaction
from abstractions.user import User
from utils.flask_utils import flask_call
from utils.cryptographic import *
from utils.view import get_difficulty_from_hash
from requests.packages.urllib3.exceptions import InsecureRequestWarning # type:ignore
from server import BLOCK_PROPOSAL, GET_USERS, GET_BLOCKCHAIN, REQUEST_TXS, SELF

# TODO: Implement Proof of Work
def proof_of_work(prev_hash:str, timestamp:float, mk_root:str, difficulty:int):
    nonce:int = 0
    #diffy:str = '0' * difficulty
    hash = double_hash(prev_hash + str(timestamp) + mk_root + str(nonce))
    #while (hash[:difficulty] is not diffy):
    while (get_difficulty_from_hash(hash) < difficulty):
        nonce += 1
        hash = double_hash(prev_hash + str(timestamp) + mk_root + str(nonce))
    return [hash, nonce, timestamp]

# TODO: Build a block
def mine_block() -> Block:
    diff = get_my_difficulty()
    #diff = 2 # testing purpose only
    last_node = get_last_block()
    txs = get_transactions()
    mkroot = MerkleTree(txs).get_root()
    me = get_my_user_obj()
    # start proof of work
    start = time.time()
    print('start mining', start)
    mined_hash, mined_nonce, mined_time = proof_of_work(last_node.hash, datetime.now().timestamp(), mkroot, diff)
    end = time.time()
    print('done mining', end)
    creation_time = end - start
    sign = me.sign(mined_hash)
    
    # create new block
    new_block = Block(mined_hash, mined_nonce, mined_time, creation_time,
                      last_node.height + 1, last_node.hash, txs,
                      True, False, mkroot, [], SELF, sign)
    return new_block

def build_block():
    # get a mined block
    new_block = mine_block()
    # chain the blocks together
    '''
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    _, blockchain, code = flask_call('GET', GET_BLOCKCHAIN)
    if blockchain and code == 200:
        b_chain = Blockchain.load_json(json.dumps(blockchain))
        if b_chain.is_chain_valid():
            b_chain.add_block(new_block)
    '''

def get_signature(hash:str) -> str:
    with open("..//vis//users//do-develop_pvk.pem", 'r') as f:
        prv_key = load_private(f.read())
    return rsa.sign(hash, prv_key, 'SHA-1')


def get_private_key() -> str:
    with open("..//vis//users//do-develop_pvk.pem", 'r') as f:
        return load_private(f.read())

def get_public_key() -> str:
    with open("..//vis//users//do-develop_pbk.pem", 'r') as f:
        return load_public(f.read())

def get_transactions():
    _, txs, code = flask_call('GET', REQUEST_TXS)
    if txs and code == 200:
        transactions = []
        for tx in txs:
            t = Transaction.load_json(json.dumps(tx))
            transactions.append(t)
        return transactions
    raise ('request_txs get error')

def get_transaction_hashes(last_node:Block) -> List[str]:
    my_txs = []
    for tx in last_node.transactions:
        my_txs.append(tx.hash)
    return my_txs

def resolve_confict():
    '''
    https://github.com/AvinashNath2/Block-Chain-Example/blob/master/Block_Chain.py
    Algorithm to position the block into the longest chain
    x longest chain refers to the blockchain that has taken the most energy to build
    x https://learnmeabitcoin.com/technical/longest-chain
    '''
    # for each neighbour check the height
    #   check if it is max_height and chain.is_chain_valid()
    #       update then track of longest chain
    # replace the chain if discovered a new, valid chain longer than current

def get_last_block():
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    _, blockchain, code = flask_call('GET', GET_BLOCKCHAIN)
    if blockchain and code == 200:
        b_chain = Blockchain.load_json(json.dumps(blockchain))
        if b_chain.is_chain_valid():
            return b_chain.block_list[-1]
    raise Exception("'Error in flask GET call, get_blockchain'")

def get_my_user_obj() -> User:
    _, users, code = flask_call('GET', GET_USERS)
    if code != 200:
        print("error in flask_call('GET', GET_USERS)")
        return
    # get my mined_blocks count
    for user in users:
        u = User.load_json(json.dumps(user))
        if u.username == SELF:
            u.privkey = get_private_key()
            u.pubkey = get_public_key()
            return u

def get_my_difficulty() -> int:
    me = get_my_user_obj()
    b_count = me.mined_blocks
    # find my difficulty
    if b_count < 10:
        my_diff = 6
    elif 10 <= b_count < 100:
        my_diff = 7
    elif 100 <= b_count < 200:
        my_diff = 8
    elif 200 <= b_count < 500:
        my_diff = 9
    else:
        my_diff = 10
    return my_diff


#############################################################################
# UNIT TEST #
#############################################################################
if __name__ == "__main__":
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    response, blockchain, code = flask_call('GET', GET_BLOCKCHAIN)
    b_chain = Blockchain.load_json(json.dumps(blockchain))
    # for b in b_chain.chain:
    #     print(b)
 
    if b_chain.is_chain_valid():
        last_node = b_chain.block_list[-1]
        llast_node = b_chain.block_list[-2]
        # last_node.transactions
        last_mkroot = last_node.merkle_root
        my_txs = last_node.transactions
        my_mkroot = MerkleTree(my_txs).get_root()
        print('previous mk root: ', last_mkroot)
        print('constructed mk root: ', my_mkroot)
    


 
    


    