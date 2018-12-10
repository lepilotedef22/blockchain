# !/usr/bin/env python3
# -*- coding: utf-! -*-

# ----------------------------------------------------- IMPORTS ----------------------------------------------------- #

from threading import Thread
from src import parse_config_node
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
        self.ip = config['node']['ip_address']
        self.authenticate_ip = config['registration']['ip_address']
        self.secret = config['registration']['secret']
        self.neighbours_ip = config['neighbours']

        self.port = 5001  # Arbitrary, given in the assignment
        self.connected_neighbours = {}  # Storing the connected neighbours to allow the communication: {ip: socket}


    # --------------------------------------------------- METHODS --------------------------------------------------- #

