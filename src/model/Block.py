# !/usr/bin/env python3
# -*- coding: utf-8 -*-

__date__ = "03.12.2018"

# ----------------------------------------------------- IMPORTS ----------------------------------------------------- #

# For types

from typing import List, Dict

# For block formatting

from time import time
from json import dumps
from struct import pack
from sys import byteorder

# For SHA256 hashing

from hashlib import sha256

# Exceptions

from src import BlockNotValidException

# ------------------------------------------------------ TYPES ------------------------------------------------------ #

Ledger = List[Dict[str, str]]


class Block:

    """
    This class deals with the blocks of the block chain
    """

    # ------------------------------------------------- CONSTRUCTOR ------------------------------------------------- #

    def __init__(

            self, index: int, ledger: Ledger, prev_hash: bytes,
            nonce: int = None, timestamp: float = None, cur_hash: bytes = None

    ) -> None:
        
        """
        Constructor of the block class
        :param index: index of the block in the block chain
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
        
        is_being_copied = timestamp is not None or cur_hash is not None

        self.index = index
        self.ledger = ledger
        self.prev_hash = prev_hash

        if is_being_copied:

            self.timestamp = timestamp
            self.cur_hash = cur_hash

        else:

            self.timestamp = time()

        chunk = bytes([index]) + dumps(self.ledger).encode('utf-8') + pack("!f", self.timestamp) + self.prev_hash

        if nonce is not None:

            # Mining is active

            self.nonce = nonce
            chunk += self.nonce.to_bytes(8, byteorder, signed=False)  # 8 bytes conversion is arbitrary,
            # need to be checked !

        # Computing hash, checking validity of the block

        comp_hash = sha256(chunk)

        if is_being_copied:

            if comp_hash != self.cur_hash:

                # Block is invalid, exception is raised

                raise BlockNotValidException("Block #{0} is invalid.".format(self.index))

        else:

            self.cur_hash = comp_hash
