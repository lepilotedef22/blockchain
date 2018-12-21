# usr/bin/env python3
# -*- coding: utf-8 -*-

# ----------------------------------------------------- IMPORTS ----------------------------------------------------- #

from typing import Dict, Optional
from time import time
from src import TransactionNotValidException


__date__ = "17.12.2018"


class Transaction:
    """
    Class dealing with transactions
    """

    TRANSACTION_FEES: float = 0.01  # Fees used to pay the miners
    BLOCK_MINED: float = 5.0  # Money offered to poorest user when a block is mined

    # ------------------------------------------------- CONSTRUCTOR ------------------------------------------------- #

    def __init__(self,
                 idx: Optional[int] = None,
                 payer: Optional[str] = None,
                 payee: Optional[str] = None,
                 amount: Optional[float] = None,
                 prev_ledger: Optional[Dict[str, float]] = None,
                 transaction_json: Optional[Dict] = None
                 ) -> None:
        """
        Constructor of Transaction
        :param idx: index of the transaction
        :param payer: who sent the money
        :param payee: who is receiving the money
        :param amount: amount (in BTM)
        :param prev_ledger: state of the accounts of the users before this transaction. Required to give money to the
            poorest and to check whether the transaction is valid. Format: {user_ip, user_money}
        :param transaction_json: if the object is instantiated from a received json
        """

        if transaction_json is None:

            # Transaction is not created from a received one, all the other args are assumed to be not None
            self.idx: int = idx
            self.payer: str = payer
            self.payee: str = payee
            self.timestamp: float = time()  # Time in EPOCH format

            if payer is not None:

                self.payer = payer

                # Transaction from node to node, fees are added
                self.amount: float = amount * (1 + self.TRANSACTION_FEES)

                available_amount = prev_ledger[self.payer]
                if self.amount > available_amount:
                    # Over-spending check
                    raise TransactionNotValidException(spent=amount,
                                                       available=available_amount)

                # Updating the ledger
                self.ledger = {}
                for user in prev_ledger:

                    if user == self.payer:

                        self.ledger[user] = prev_ledger[user] - self.amount

                    elif user == self.payee:

                        self.ledger[user] = prev_ledger[user] + self.amount / (1 + self.TRANSACTION_FEES)

                    else:

                        self.ledger[user] = prev_ledger[user]

            else:

                self.payer = ""

                # Transaction from network to node, when a block is mined
                self.amount = amount

                # Updating the ledger
                self.ledger = {}
                for user in prev_ledger:

                    if user == self.payee:

                        self.ledger[user] = prev_ledger[user] + self.amount

                    else:

                        self.ledger[user] = prev_ledger[user]

        else:

            # Transaction created from a received one, other args are assumed to be None
            # No over-spending check, assuming that the sending node has already performed it
            self.idx = transaction_json['idx']
            self.payer = transaction_json['payer']
            self.payee = transaction_json['payee']
            self.amount = transaction_json['amount']
            self.timestamp = transaction_json['timestamp']
            self.ledger = transaction_json['ledger']

    # --------------------------------------------------- METHODS --------------------------------------------------- #

    def get_json(self) -> Dict:
        """
        Returns the attributes of the object as a json
        :return: json with the attributes
        """

        return {'idx': self.idx,
                'payer': self.payer,
                'payee': self.payee,
                'amount': self.amount,
                'ledger': self.ledger,
                'timestamp': self.timestamp}

    def get_fees(self) -> float:
        """
        Returns the fees of a transaction
        :return: Transaction.TRANSACTION_FEES * amount
        """

        if self.payer != "":

            # Transaction from node to node
            return (self.amount * self.TRANSACTION_FEES) / (1 + self.TRANSACTION_FEES)

        else:

            # Transaction from network to node, no fees
            return 0
