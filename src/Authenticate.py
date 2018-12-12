# !/usr/bin/env python3
# -*- coding: utf-8 -*-

# ----------------------------------------------------- IMPORTS ----------------------------------------------------- #

from typing import Dict, Tuple
from threading import Thread
from src import parse_config_auth_center, receive, send, Bitcop, BitcopAuthenticate
from socket import socket
from random import getrandbits
from hashlib import sha256
from sys import byteorder


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
        self.all_nodes: Dict[str, str] = conf['nodes']
        self.nodes_to_connect: Dict[str, str] = conf['nodes']

    # --------------------------------------------------- METHODS --------------------------------------------------- #

    def __authenticate(self,
                       server_sock: socket,
                       client_sock: socket,
                       client_address: Tuple[str, int]
                       ) -> None:
        """
        Authenticates the node to the authentication center. Once the node is authenticated, it is removed from the
        attribute nodes_to_connect. The authentication sequence is based on the challenge-response scheme:
            1) node sends its user_name to the auth_center to indicate that it wants to be authenticated
            2) auth_center replies with a Nonce
            3) node replies with (user_name, sha256(nonce|secret)) with secret the shared secret
            4) auth_center replies with ok
        If at any point something goes wrong, each host can send an ABORT message.
        :param server_sock: socket of the authenticate server
        :param client_sock: socket of the node requesting authentication
        :param client_address: client address: (ip, port)
        """

        # Request

        auth_req = receive(server_sock)
        req_code = auth_req.get_request()['code']
        user_name = auth_req.get_request()['data']
        node_ip = client_address[0]

        if req_code == Bitcop.AUTH_ABORT:

            # Client aborted the operation
            return

        elif req_code != Bitcop.AUTH_REQ:

            # Code does not match that of a request
            abort_req = BitcopAuthenticate(Bitcop.AUTH_ABORT,
                                           'abort')
            send(client_sock, abort_req)
            return

        # Challenge

        nonce: int = getrandbits(8 * Bitcop.NUMBER_BYTES_NONCE)
        chal_req = BitcopAuthenticate(Bitcop.AUTH_CHAL, nonce)
        send(server_sock, chal_req)

        # Response

        secret = self.nodes_to_connect[node_ip]
        hash_arg = nonce.to_bytes(Bitcop.NUMBER_BYTES_NONCE, byteorder) + secret.encode('latin-1')
        check = (user_name, sha256(hash_arg).digest())

    # ----------------------------------------------------- RUN ----------------------------------------------------- #

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

                # Creating the thread handling the client socket
                client_thread = Thread(target=self.__authenticate, args=[auth_server,
                                                                         node_sock,
                                                                         node_address])

                # Starting the thread
                client_thread.start()
