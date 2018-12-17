# usr/bin/env python3
# -*- coding: utf-8 -*-

# ----------------------------------------------------- IMPORTS ----------------------------------------------------- #

from typing import Dict
from time import time
from src import TransactionNotValidException


__date__ = "17.12.2018"


class Transaction:
    """
    Class dealing with transactions
    """

    # ------------------------------------------------- CONSTRUCTOR ------------------------------------------------- #

    def __init__(self,
                 idx: int,
                 payer: str,
                 payee: str,
                 amount: float,
                 prev_ledger: Dict[str, float]
                 ) -> None:
        """
        Constructor of Transaction
        :param idx: index of the transaction
        :param payer: who sent the money
        :param payee: who is receiving the money
        :param amount: amount (in BTM)
        :param prev_ledger: state of the accounts of the users before this transaction. Required to give money to the
            poorest and to check whether the transaction is valid. Format: {user_ip, user_money}
        """

        self.idx: int = idx
        self.payer: str = payer
        self.payee: str = payee
        self.amount: float = amount
        self.timestamp: float = time()  # Time in EPOCH format

        available_amount = prev_ledger[self.payer]
        if self.amount > available_amount:

            raise TransactionNotValidException(spent=amount,
                                               available=available_amount)

        # Updating the ledger

        self.ledger = {}
        for user in prev_ledger:

            if user == self.payer:

                self.ledger[user] = prev_ledger[user] - self.amount

            elif user == self.payee:

                self.ledger[user] = prev_ledger[user] + self.amount

            else:

                self.ledger[user] = prev_ledger[user]
