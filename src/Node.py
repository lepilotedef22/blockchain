# !/usr/bin/env python3
# -*- coding: utf-! -*-

# ----------------------------------------------------- IMPORTS ----------------------------------------------------- #

from typing import List
from threading import Thread
from src import parse_config_node, Blockchain, Bitcop, BitcopAuthenticate, send, receive
from socket import socket, SHUT_RDWR
from hashlib import sha256
from sys import byteorder, argv
from time import sleep


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
        config = parse_config_node(node_idx)
        self.username: str = config['node']['username']
        self.ip: str = config['node']['ip_address']  # Alias loopback address (cf. assignment)
        self.authenticate_ip: str = config['registration']['ip_address']
        self.secret: str = config['registration']['secret']
        self.neighbours_ip: List[str] = config['neighbours']

        self.server_port: int = 5001  # Arbitrary, given in the assignment
        self.blockchain: Blockchain = Blockchain()
        self.authenticated: bool = False  # Authenticated to the network ?
        self.nodes: List[str] = None  # IP of all the nodes on the network
        self.server_socket: socket = None  # Server socket of the node
        self.balance = 0

    # --------------------------------------------------- METHODS --------------------------------------------------- #

    def stop(self) -> None:
        """
        Stops the thread
        """

    def __authenticate(self,
                       snd_socket: socket
                       ) -> None:
        """
        Authenticates the node to the authentication center. Once the node is authenticated, its authenticated attribute
        is switched to True. The authentication sequence is based on the challenge-response scheme:
            1) node sends its user_name to the auth_center to indicate that it wants to be authenticated
            2) auth_center replies with a Nonce
            3) node replies with (user_name, sha256(nonce|secret)) with secret the shared secret
            4) auth_center replies with the list of nodes IP
        If at any point something goes wrong, each host can send an ABORT message.
        :param snd_socket: the socket used to communicate with the authentication center
        """

        try:

            # Request

            request = BitcopAuthenticate(Bitcop.AUTH_REQ,
                                         self.username)
            send(snd_socket, request)

            # Challenge

            auth_challenge = receive(snd_socket)
            chal_code = auth_challenge.get_request()['code']

            if chal_code == Bitcop.AUTH_ABORT:

                # Server aborted the operation
                return

            elif chal_code != Bitcop.AUTH_CHAL:

                # Code does not match that of a challenge
                abort_req = BitcopAuthenticate(Bitcop.AUTH_ABORT,
                                               'abort')
                send(snd_socket, abort_req)
                return

            nonce = auth_challenge.get_request()['data']

            # Response

            hash_arg = nonce.to_bytes(Bitcop.NUMBER_BYTES_NONCE, byteorder) + self.secret.encode('utf-8')
            resp_data = [self.username, sha256(hash_arg).hexdigest()]

            response = BitcopAuthenticate(Bitcop.AUTH_RESP,
                                          resp_data)
            send(snd_socket, response)

            # OK

            auth_ok = receive(snd_socket)
            ok_code = auth_ok.get_request()['code']

            if ok_code == Bitcop.AUTH_OK:

                # Node successfully authenticated
                self.authenticated = True  # Stopping the authentication loop
                self.nodes = auth_ok.get_request()['data']
                #print("Node {} successfully authenticated on the Bitcom network".format(self.username))

            elif ok_code == Bitcop.AUTH_ABORT:

                # Server aborted the operation
                return

            else:

                # Code does not match that of an auth_ok
                abort_req = BitcopAuthenticate(Bitcop.AUTH_ABORT,
                                               'abort')
                send(snd_socket, abort_req)
                return

        except RuntimeError:
            #print("Socket communication broken at node {0}:{1}".format(self.ip,
            #                                                           self.authenticate_ip))
            return

    def __serve_forever(self,
                        server_socket: socket
                        ) -> None:
        """
        Method running in the server thread.
        :param server_socket: socket receiving the requests
        """
        #print("Serving...")

    def __mine(self) -> None:
        """
        Method used to mine blocks and to send them to neighbours
        """
        #print("Mining...")

    # ----------------------------------------------------- RUN ----------------------------------------------------- #

    def run(self) -> None:
        """
        Main method of the Node thread :
            1. tries to be authenticated on the network by the authentication center
            2. starts the server
        """

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ AUTHENTICATION ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #

        with socket() as auth_client:

            # Creating a socket with default mode: IPv4/TCP
            is_bound = False
            auth_server_address = (self.authenticate_ip,
                                   self.server_port)
            auth_client_address = None
            while not is_bound:

                try:
                    auth_client.bind((self.ip, 0))  # OS takes care of free port allocation
                    auth_client.connect(auth_server_address)
                    auth_client_address = auth_client.getsockname()
                    is_bound = True

                except OSError:
                    #print("Server at {0}:{1} cannot be reached".format(self.authenticate_ip,
                    #                                                   self.server_port))
                    #print("Please try again later...")
                    return

            while not self.authenticated:
                # Trying to be authenticated on the network
                self.__authenticate(auth_client)

            # Shutting down connection with authenticate center

            try:

                auth_client.shutdown(SHUT_RDWR)  # Flag: no more send or rcv to expect from auth_client
                auth_client.close()
                #print("Socket at {0}:{1} closed".format(auth_client_address[0],
                #                                        auth_client_address[1]))

            except OSError:

                pass
                #print("Socket at {0}:{1} not closed properly".format(auth_client_address[0],
                #                                                     auth_client_address[1]))

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ SERVER ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #

        with socket() as node_server:

            # Creating a socket with default mode: IPv4/TCP
            is_bound = False
            while not is_bound:

                try:
                    node_server.bind((self.ip, self.server_port))
                    is_bound = True

                except OSError:
                    #print("Address {0}:{1} already used".format(self.ip, self.server_port))
                    sleep(1)  # Waiting one second before attempting to bind again

            # Creating and starting the server thread
            server_thread = Thread(target=self.__serve_forever,
                                   args=[node_server])
            server_thread.start()

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ MINING ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #

        mining_thread = Thread(target=self.__mine)
        mining_thread.start()


# ------------------------------------------------------- MAIN ------------------------------------------------------- #

if __name__ == "__main__":

    if len(argv) == 1:

        # No arg passed
        idx = int(input("Insert node index: "))

    else:

        # Args passed, first one is node index
        idx = argv[1]

    node = Node(idx)
    node.start()
