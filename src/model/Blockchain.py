# !/usr/bin/env python3
# -*- coding: utf-8 -*-

__date__ = "04.12.2018"

# ----------------------------------------------------- IMPORTS ----------------------------------------------------- #

# From module

from src import Block

# For types

from typing import List


class Blockchain:

    """
    This class deals with the Blockchain, ie the chain of blocks. It is encoded as a list of blocks
    """

    # ------------------------------------------------- CONSTRUCTOR ------------------------------------------------- #

    def __init__(self) -> None:

        """
        Constructor of the blockchain
        """

        self.blockchain = []

    # --------------------------------------------------- METHODS --------------------------------------------------- #

    def add(self, new_block: Block) -> None:

        """
        Adds a new block at the end of the chain
        :param new_block: block to be added
        :return: None
        """

        self.blockchain.append(new_block)

    def get_last_block(self) -> Block:

        """
        Returns the last block of the chain
        :return: The last block of the chain
        """

        return self.blockchain[-1]

    def get_blocks_between_indexes(self, index_1: int, index_2: int) -> List[Block]:

        """
        Returns list of blocks of the blockchain between two indexes. If index_2 is greater than the length of the
        blockchain, the returned list stops at the last element of the blockchain
        :param index_1: starting index
        :param index_2: stopping index (not included)
        :return: a list of blocks between the two indexes
        """

        if index_2 > len(self.blockchain):

            # index_2 is bigger than the maximum possible value

            return self.blockchain[index_1:]

        else:

            return self.blockchain[index_1: index_2]
