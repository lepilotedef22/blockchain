# !/usr/bin/env python3
# -*- coding: utf-! -*-

# ----------------------------------------------------- IMPORTS ----------------------------------------------------- #

# Typing
from typing import List, Dict

from threading import Thread
from src import parse_config_node, Blockchain, Bitcop, BitcopAuthenticate, send, receive
from socket import socket
from hashlib import sha256
from sys import byteorder

__date__ = "07.12.2018"


class Node(Thread):
    """
    Class representing a node of the network.
    """

    # ------------------------------------------------- CONSTRUCTOR ------------------------------------------------- #

    def __init__(self,
                 node_idx: int
                 ) -> None:
        """
        Constructor of the Node class
        :param node_idx: index of the node used to find the config file to parse
        """

        super().__init__()

        # Parsing config files
        # TODO : update network topology according to assignment
        config = parse_config_node(node_idx)
        self.username: str = config['node']['username']
        self.ip: str = config['node']['ip_address']  # Alias loopback address (cf. assignment)
        self.authenticate_ip: str = config['registration']['ip_address']
        self.secret: str = config['registration']['secret']
        self.neighbours_ip: List[str] = config['neighbours']

        self.port: int = 5001  # Arbitrary, given in the assignment
        self.connected_neighbours: Dict[str, socket] = {}  # Storing the connected neighbours to allow the
        # communication: {ip: socket}
        self.blockchain: Blockchain = Blockchain()
        self.authenticated: bool = False  # Authenticated to the network ?

    # --------------------------------------------------- METHODS --------------------------------------------------- #

    def __authenticate(self, snd_socket: socket) -> None:
        """
        Authenticates the node to the authentication center. Once the node is authenticated, its authenticated attribute
        is switched to True
        :param snd_socket: the socket used to communicate with the authentication center
        """

        # Communication setup

        auth_server_address = (self.authenticate_ip,
                               self.port)

        # Request

        request = BitcopAuthenticate(Bitcop.AUTH_REQ,
                                     self.username)
        send(snd_socket,
             auth_server_address,
             request)

        # Challenge

        auth_challenge = receive(snd_socket)
        chal_code = auth_challenge.get_request()['code']

        if chal_code != Bitcop.AUTH_CHAL:

            # Code does not match that of a challenge
            abort_req = BitcopAuthenticate(Bitcop.AUTH_ABORT,
                                           'abort')
            send(snd_socket,
                 auth_server_address,
                 abort_req)
            return

        elif chal_code == Bitcop.AUTH_ABORT:

            # Server aborted the operation
            return

        nonce = auth_challenge.get_request()['data']

        # Response

        hash_arg = nonce.to_bytes(Bitcop.NUMBER_BYTES_NONCE, byteorder) + self.secret.encode('latin-1')
        resp_data = (self.username, sha256(hash_arg))

        response = BitcopAuthenticate(Bitcop.AUTH_RESP,
                                      resp_data)
        send(snd_socket,
             auth_server_address,
             response)

        # OK

        auth_ok = receive(snd_socket)
        ok_code = auth_ok.get_request()['code']

        if ok_code == Bitcop.AUTH_OK:

            # Node successfully authenticated
            self.authenticated = True  # Stopping the authentication loop
            print("Node {0} successfully authenticated on the Bitcom network".format(self.username))

        elif ok_code == Bitcop.AUTH_ABORT:

            # Server aborted the operation
            return

        else:

            # Code does not match that of an auth_ok
            abort_req = BitcopAuthenticate(Bitcop.AUTH_ABORT,
                                           'abort')
            send(snd_socket,
                 auth_server_address,
                 abort_req)
            return

    # ----------------------------------------------------- RUN ----------------------------------------------------- #

    def run(self) -> None:
        """
        Main method of the Node thread :
            1. tries to be authenticated on the network by the authentication center
        """

        with socket() as sock:
            # Creating as socket with default mode : IPv4 and TCP
            sock.bind((self.ip, self.port))

            while not self.authenticated:
                # Trying to be authenticated on the network
                self.__authenticate(sock)
