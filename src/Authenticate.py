# !/usr/bin/env python3
# -*- coding: utf-8 -*-

# ----------------------------------------------------- IMPORTS ----------------------------------------------------- #

from typing import Dict
from threading import Thread
from src import parse_config_auth_center, AuthCenterClientThread
from socket import socket


__date__ = "12.12.2018"


class Authenticate(Thread):

    """
    This class handles the authentication of the nodes on the Bitcom network. The authentication process is based on the
    challenge-response scheme : 1) node requests a authentication by sending its user_name
                                2) server responds with a nonce (coded on Bitcop.NUMBER_OF_BYTES bytes)
                                3) node responds with (user_name, sha256(nonce|secret)), secret being the shared secret
                                4) server responds with OK
    At any time, the communication can be stopped using the ABORT message
    """

    # ------------------------------------------------- CONSTRUCTOR ------------------------------------------------- #

    def __init__(self) -> None:
        """
        Constructor of the authenticate server
        """

        super().__init__()

        # Parsing config file
        conf = parse_config_auth_center()
        self.ip: str = conf['ip_address']
        self.port: int = 5001
        self.nodes: Dict[str, str] = conf['nodes']

    # --------------------------------------------------- METHODS --------------------------------------------------- #

    def run(self) -> None:
        """
        Main process of the Authentication thread. Its aim is to start the authenticate server, and then to intercept
        client requests that will be handled in other threads.
        """

        with socket() as auth_server:

            # Setting up connection
            auth_server_address = (self.ip, self.port)
            auth_server.bind(auth_server_address)
            auth_server.listen(5)  # Queue up to 5 client sockets

            # ---------------------------------------------- MAIN LOOP ---------------------------------------------- #

            while True:

                # Intercepting new client requests
                node_sock, node_address = auth_server.accept()

                # Creating the handling thread
                auth_client_thread = AuthCenterClientThread(auth_server,
                                                            node_sock,
                                                            node_address)
                # Starting the thread
                auth_client_thread.start()


