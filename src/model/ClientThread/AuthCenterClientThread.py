# !/usr/bin/env python3
# -*- coding: utf-8 -*-

# ----------------------------------------------------- IMPORTS ----------------------------------------------------- #

from typing import Tuple
from src import ClientThread
from socket import socket


__date__ = "12.12.2018"


class AuthCenterClientThread(ClientThread):
    """
    This thread subclass is used to handle a client trying to authenticate on the Bitcom network
    """

    # ------------------------------------------------- CONSTRUCTOR ------------------------------------------------- #

    def __init__(self,
                 server_sock: socket,
                 client_sock: socket,
                 client_address: Tuple[str, int]
                 ) -> None:
        """
        Constructor of AuthCenterClientThread
        :param server_sock: socket of the server that intercepted the authentication request
        :param client_sock: socket of the node that wants to be authenticated
        :param client_address: client address: (ip_address, port)
        """

        super().__init__(server_sock,
                         client_sock,
                         client_address)

    # --------------------------------------------------- METHODS --------------------------------------------------- #

    def run(self) -> None:
        """
        Main process of the thread, handling of the client request
        """

