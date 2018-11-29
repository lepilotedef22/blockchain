# !/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
This module deals with the authenticate center. It is mainly running an authentication server. It authenticates the
clients based on the 'challenge-response' scheme :
    Client calls for a connection
    Server responds with a nonce
    Clients responds with a tuple (username, hash_sha256(nonce+password))
    Server ends with 'OK' 
"""

__date__ = "30/11/2018"

# ----------------------------------------------------- IMPORTS ----------------------------------------------------- #

from src import AuthenticateRX
from hashlib import sha256
import threading


class Authenticate(threading):

    """
    This class is responsible for the authenticate server used to validate the nodes on the network
    """

    # ------------------------------------------------- CONSTRUCTOR ------------------------------------------------- #

    def __init__(self) -> None:

        """
        Constructor of the authenticate server
        """

        self.auth_rx = AuthenticateRX("42.42.42.42", 4242)  # TODO parse ini to get ip

    # --------------------------------------------------- METHODS --------------------------------------------------- #

    def run(self) -> None:

        """
        Overriding the run method of threading. Main loop executed to intercept the authentication requests from
        the nodes and to manage them.
        """

        while True:

            # Main loop of the authentication server
            # TODO implement the main loop

            print("lolilol")

