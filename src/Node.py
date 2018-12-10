# !/usr/bin/env python3
# -*- coding: utf-! -*-

# ----------------------------------------------------- IMPORTS ----------------------------------------------------- #

from threading import Thread
from src import parse_config_node, Blockchain
from socket import socket


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
        self.username = config['node']['username']
        self.ip = config['node']['ip_address']  # Alias loopback address (cf. assignment)
        self.authenticate_ip = config['registration']['ip_address']
        self.secret = config['registration']['secret']
        self.neighbours_ip = config['neighbours']

        self.port = 5001  # Arbitrary, given in the assignment
        self.connected_neighbours = {}  # Storing the connected neighbours to allow the communication: {ip: socket}
        self.blockchain = Blockchain()
        self.authenticated = False  # Authenticated to the network ?

    # --------------------------------------------------- METHODS --------------------------------------------------- #

    def __authenticate(self, send_socket: socket) -> None:

        """
        Authenticates the node to the authentication center. Once the node is authenticated, its authenticated attribute
        is switched to True
        :param send_socket: the socket used to communicate with the authentication center
        """

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
