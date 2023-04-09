# TODO: Make Merkle tree structure
import sys
sys.path.insert(0,"..")
from abstractions.transaction import Transaction
from utils.flask_utils import flask_call
from utils.cryptographic import *
from typing import List
import requests 
from requests.packages.urllib3.exceptions import InsecureRequestWarning # type:ignore
class Node:
    def  __init__(self, hash, left=None, right=None):
        self.left = left
        self.right = right
        self.hash = hash
    
class MerkleTree:
    def __init__(self, txs): # txs is list of transactions (changed block.py line 102)
        self.data = None
        self.leaf_nodes = []
        for tx in txs:
            self.leaf_nodes.append(Node(hash_function(tx.hash)))
        self.root = None
        self.build_tree()

    def build_tree(self):
        left = right = None
        tree = self.leaf_nodes
        while len(tree) > 1:
            parents = []
            for i in range(0, len(tree), 2):
                left = tree[i]
                right = tree[i + 1] if i + 1 < len(tree) else tree[i]
                parent_hash = hash_function(left.hash + right.hash)
                parent = Node(parent_hash, left, right)
                parents.append(parent)
            tree = parents 
        self.root = tree[0]

    def get_root(self):
        return self.root

    def print_tree(self) -> None:
        """Prints the merkle tree"""
        self.__print_tree_recursive(self.root)

    def __print_tree_recursive(self, node: Node) -> None:
        """Recursively prints the merkle tree"""
        if node is None:
            print("node is none")
            return
        print(node.hash)
        self.__print_tree_recursive(node.left)
        self.__print_tree_recursive(node.right)


    

    