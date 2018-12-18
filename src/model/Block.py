# !/usr/bin/env python3
# -*- coding: utf-8 -*-

__date__ = "03.12.2018"

# ----------------------------------------------------- IMPORTS ----------------------------------------------------- #


from typing import List, Dict, Optional
from random import getrandbits

from time import time
from json import dumps
from struct import pack
from sys import byteorder

from hashlib import sha256

from src import Transaction

# Exceptions

from src import BlockNotValidException

# ------------------------------------------------------ TYPES ------------------------------------------------------ #

Ledger = List[Dict[str, str]]


class Block:

    """
    This class deals with the blocks of the block chain
    """

    NUMBER_BYTES_NONCE: int = 8

    # ------------------------------------------------- CONSTRUCTOR ------------------------------------------------- #

    def __init__(self,
                 idx: Optional[int] = None,
                 prev_hash: Optional[bytes] = None,
                 transaction_list: Optional[List[Transaction]] = None,
                 nonce: Optional[int] = None,
                 timestamp: Optional[float] = None,
                 cur_hash: Optional[bytes] = None,
                 block_json: Optional[Dict] = None
                 ) -> None:
        
        """
        Constructor of the block class
        :param idx: index of the block in the block chain
        :param ledger: current state of the data to be saved in the block. It is a list of all the pending transactions
        committed between two blocks. A transaction is the state of the network i.e. a dictionary :
            transaction : {"user" : user_money}
        :param prev_hash: hash of the previous block in the block chain
        :param nonce: nonce used to mine the block
        :param timestamp: optional value (used only if the block is being created based on a received block 
        broad casted by another node) for the time at which the block was emitted
        :param cur_hash: optional value (used only if the block is being created based on a received block 
        broad casted by another node) for the current hash of the block
        """
        
        if block_json is None:

            self.idx: int = idx
            self.prev_hash: bytes = prev_hash
            self.transaction_list: List[Transaction] = transaction_list
            self.nonce: int = getrandbits(8 * self.NUMBER_BYTES_NONCE)
            self.timestamp: float = time()

            hash_arg = self.prev_hash

            for transaction in self.transaction_list:
                hash_arg += dumps(transaction.get_json()).encode('utf-8')

            hash_arg += self.nonce

            self.cur_hash = sha256(hash_arg)

        else:

            # Transaction created from a received one, other args are assumed to be None
            # No over-spending check, assuming that the sending node has already performed it

            self.idx = block_json['idx']
            self.prev_hash = block_json['prev_hash']
            self.transaction_list = block_json['transaction_list']
            self.nonce = block_json['nonce']
            self.timestamp = block_json['timestamp']
            self.cur_hash = block_json['cur_hash']



    # --------------------------------------------------- METHODS --------------------------------------------------- #

    def get_json(self) -> Dict:
        """
        Returns the attributes of the object as a json
        :return: json with the attributes
        """

        return {'idx': self.idx,
                'prev_hash': self.prev_hash,
                'transaction_list': self.transaction_list,
                'nonce': self.nonce,
                'timestamp': self.timestamp,
                'cur_hash': self.cur_hash}
