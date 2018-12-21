# !/usr/bin/env python3
# -*- coding: utf-8 -*-

__date__ = "18.12.2018"

# ----------------------------------------------------- IMPORTS ----------------------------------------------------- #


from typing import List, Dict, Optional
from random import getrandbits
from time import time
from json import dumps
from hashlib import sha256
from src import Transaction, BlockNotValidException, Bitcop


# ------------------------------------------------------ TYPES ------------------------------------------------------ #


class Block:
    """
    Class dealing with the Blocks
    """

    # ------------------------------------------------- CONSTRUCTOR ------------------------------------------------- #

    def __init__(self,
                 idx: Optional[int] = None,
                 prev_hash: Optional[str] = None,
                 transactions: Optional[List[Transaction]] = None,
                 block_json: Optional[Dict] = None
                 ) -> None:
        """
        Constructor of the block class
        :param idx: index of the block in the block chain
        :param prev_hash: hash of the previous block in the block chain
        :param transactions: list of all the transaction between the previous block and this one
        """
        
        if block_json is None:

            self.idx: int = idx
            self.prev_hash: str = prev_hash
            self.transactions: List[Transaction] = transactions
            self.nonce: int = getrandbits(8 * Bitcop.NUMBER_BYTES_NONCE)
            self.timestamp: float = time()
            self.hash: str = self.block_computation()

            if self.hash[:Bitcop.NUMBER_0_MINING] != Bitcop.NUMBER_0_MINING * "0":

                # Mined block is not valid
                message = "Block is not valid for mining. hash is {}".format(self.hash)
                raise BlockNotValidException(message=message)

        else:

            self.idx = block_json['idx']
            self.prev_hash = block_json['prev_hash']
            self.transactions = [Transaction(transaction_json=transaction_json)
                                 for transaction_json in block_json['transactions']]
            self.nonce = block_json['nonce']
            self.timestamp = block_json['timestamp']
            self.hash = block_json['hash']
            hash_check = self.block_computation()

            if self.hash != hash_check:

                raise BlockNotValidException(computed_hash=hash_check,
                                             given_hash=self.hash)

# ----------------------------------------------------- METHODS ----------------------------------------------------- #

    def get_json(self) -> Dict:
        """
        Returns the attributes of the object as a json
        :return: json with the attributes
        """

        return {'idx': self.idx,
                'prev_hash': self.prev_hash,
                'transactions': [transaction.get_json() for transaction in self.transactions],
                'nonce': self.nonce,
                'timestamp': self.timestamp,
                'hash': self.hash}

    def block_computation(self) -> str:
        """
        Computes the hash of the current block based on the previous one
        :return: hash of the block in bytes
        """

        hash_arg = str(self.idx).encode('utf-8') + self.prev_hash.encode('utf-8')
        for transaction in self.transactions:

            hash_arg += dumps(transaction.get_json()).encode('utf-8')

        hash_arg += str(self.nonce).encode('utf-8') + str(self.timestamp).encode('utf-8')
        return sha256(hash_arg).hexdigest()
