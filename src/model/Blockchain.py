# !/usr/bin/env python3
# -*- coding: utf-8 -*-

# ----------------------------------------------------- IMPORTS ----------------------------------------------------- #

from src import Block, Transaction
from typing import List, Optional
from time import strftime, localtime


__date__ = "04.12.2018"


class Blockchain:
    """
    This class deals with the Blockchain, ie the chain of blocks. It is encoded as a list of blocks
    """

    # ------------------------------------------------- CONSTRUCTOR ------------------------------------------------- #

    def __init__(self) -> None:

        """
        Constructor of the blockchain
        """
        self.chain = []

    # --------------------------------------------------- METHODS --------------------------------------------------- #

    def add(self,
            new_block: Block
            ) -> None:
        """
        Adds a new block at the end of the chain
        :param new_block: block to be added
        :return: None
        """

        self.chain.append(new_block)

    def get_last_block(self) -> Optional[Block]:
        """
        Returns the last block of the chain
        :return: The last block of the chain
        """

        if len(self.chain) == 0:

            # Chain is empty, waiting for Big Bang Block to be added
            return None

        else:

            # Chain not empty
            return self.chain[-1]

    def get_blocks_between_indexes(self, index_1: int, index_2: int) -> List[Block]:
        """
        Returns list of blocks of the blockchain between two indexes. If index_2 is greater than the length of the
        blockchain, the returned list stops at the last element of the blockchain
        :param index_1: starting index
        :param index_2: stopping index (not included)
        :return: a list of blocks between the two indexes
        """

        if index_2 > len(self.chain):

            # index_2 is bigger than the maximum possible value

            return self.chain[index_1:]

        else:

            return self.chain[index_1: index_2]

    def get_transactions(self,
                         target_ip: str
                         ) -> List[str]:
        """
        Returns the list of the transactions to be displayed in the shell
        :param target_ip: ip of interest
        :return: the list of transactions formatted in a suitable way for display
        """

        transaction_list: List[str] = []
        for block in self.chain:

            for transaction in block.transactions:

                if transaction.payer == target_ip:

                    date: str = strftime("%a, %d %b %Y %H:%M:%S", localtime(transaction.timestamp))
                    transaction_list.append("{}: [-] {} -> {} {:.2f} BTM: {:.2f} BTM".format(
                        date,
                        transaction.payer,
                        transaction.payee,
                        transaction.amount,
                        transaction.ledger[target_ip]
                    ))

                elif transaction.payee == target_ip:

                    amount = transaction.amount / (1 + Transaction.TRANSACTION_FEES)
                    date: str = strftime("%a, %d %b %Y %H:%M:%S", localtime(transaction.timestamp))
                    transaction_list.append("{}: [+] {} -> {} {:.2f} BTM: {:.2f} BTM".format(
                        date,
                        transaction.payer,
                        transaction.payee,
                        amount,
                        transaction.ledger[target_ip]
                    ))

        transaction_list.reverse()
        return transaction_list
