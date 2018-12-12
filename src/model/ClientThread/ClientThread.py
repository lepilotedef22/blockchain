# !/usr/bin/env
# -*- coding: utf-8 -*-

# ----------------------------------------------------- IMPORTS ----------------------------------------------------- #

from typing import Tuple
from threading import Thread
from abc import ABC
from socket import socket


__date__ = "12.12.2018"


class ClientThread(Thread, ABC):
    """
    The thread of this class handles the client socket requests received in the main loop of the different kinds of
    server. It will be inherited in subclasses specific to the authenticate or node servers.
    """

    # ------------------------------------------------- CONSTRUCTOR ------------------------------------------------- #

    def __init__(self,
                 server_sock: socket,
                 client_sock: socket,
                 client_address: Tuple[str, int]
                 ) -> None:
        """
        Constructor of the abstract class ClientThread
        :param server_sock: server socket
        :param client_sock: client socket
        :param client_address: client address: (ip_address, port)
        """

        super().__init__()
        self.server_sock = server_sock
        self.client_sock = client_sock
        self.client_address = client_address
