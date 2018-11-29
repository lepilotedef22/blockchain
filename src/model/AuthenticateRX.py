# !/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
This subclass of RX deals with the reception of authentication messages. It specialises the features of its
superclass
"""

__date__ = "30/11/2018"

# ----------------------------------------------------- IMPORTS ----------------------------------------------------- #

from src import RX


class AuthenticateRX(RX):

    """
    This class ensures the reception of authentication messages and their treatment
    """

    # ------------------------------------------------- CONSTRUCTOR ------------------------------------------------- #

    def __init__(self, ip: str, port: int) -> None:

        """
        Constructor of the authenticateRX class
        :param ip: ip address of the RX
        :param port: port of the RX
        """

        super().__init__(ip, port)

