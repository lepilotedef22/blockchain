# usr/bin/env python3
# -*- coding: utf-8 -*-

# ----------------------------------------------------- IMPORTS ----------------------------------------------------- #

from typing import Optional, List


__date__ = "17.12.2018"


class TransactionNotValidException(Exception):
    """
    Exception raised when a user attempts to spend more money than he or she possesses
    """

    # ------------------------------------------------- CONSTRUCTOR ------------------------------------------------- #

    def __init__(self,
                 spent: Optional[float] = None,
                 available: Optional[float] = None,
                 nodes: Optional[List[str]] = None,
                 message: Optional[str] = None
                 ) -> None:
        """
        Constructor of TransactionNotValidException
        :param spent: money the user tried to spend
        :param available: money available to spend
        :param nodes: list of nodes of the network
        :param message: message o be passed to the exception
        """

        if spent is not None and available is not None:

            # If message is None, the passed args are spent and available
            message: str = "Transaction not valid.\nSpent: {} BTM\nAvailable: {} BTM".format(spent, available)

        elif nodes is not None:

            # Credit : https://stackoverflow.com/questions/7568627/using-python-string-formatting-with-lists
            formatted_list = ['{:>3}' for item in nodes]
            string_list = '\n'.join(formatted_list)
            nodes_string = string_list.format(*nodes)
            message = "Payee IP is not valid. Correct IP are:\n{}".format(nodes_string)

        super().__init__(message)
        self.message = message
