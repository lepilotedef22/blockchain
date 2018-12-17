# !/usr/bin/env python3
# -*- coding: utf-! -*-

# ----------------------------------------------------- IMPORTS ----------------------------------------------------- #

from typing import List, Dict
from threading import Thread, Lock
from src import parse_config_node, Blockchain, Bitcop, BitcopAuthenticate, send, receive, Transaction, \
    TransactionNotValidException
from socket import socket
from hashlib import sha256
from sys import byteorder
from time import sleep
import logging


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
        self.is_serving = False  # Node IP is serving ?
        self.is_mining = False  # Node is mining ?
        self.transaction_idx: int = 0  # Index of the last transaction
        self.pending_transactions: List[Transaction] = []  # List of transactions waiting to be mined into a block
        self.ledger: Dict[str, float] = None  # Amount on the accounts of all the users

    # --------------------------------------------------- METHODS --------------------------------------------------- #

    def stop(self) -> None:
        """
        Stops the threads
        """

        with Lock():

            # Shutting down the threads
            self.is_mining = False
            self.is_serving = False

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
                self.ledger = {ip: 0 for ip in self.nodes}  # Initializing balance of each user to 0 BTM
                self.nodes.remove(self.ip)  # Removing own ip address from list of other users ip
                logging.info("Node {} successfully authenticated on the Bitcom network".format(self.username))

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
            logging.error("Socket communication broken at node {}:{}".format(self.ip,
                                                                             self.authenticate_ip))
            return

    def __serve_forever(self) -> None:
        """
        Method running in the server thread.
        """

        with socket() as node_server:

            # Creating a socket with default mode: IPv4/TCP
            is_bound = False
            while not is_bound:

                try:
                    node_server.bind((self.ip, self.server_port))
                    is_bound = True
                    self.server_socket = node_server

                except OSError:
                    logging.info("Address {}:{} already used".format(self.ip, self.server_port))
                    sleep(1)  # Waiting one second before attempting to bind again

            with Lock():
                serving_condition: bool = self.is_serving

            while serving_condition:

                # Serve...

                # End of loop
                with Lock():
                    serving_condition: bool = self.is_serving

        # Returning from thread once the job is done
        return

    def __mine(self) -> None:
        """
        Method used to mine blocks and to send them to neighbours
        """

        with Lock():

            mining_condition: bool = self.is_mining

        while mining_condition:

            # Mine...

            # End of mining loop

            with Lock():
                mining_condition = self.is_mining

        # Returning from thread once the job is done
        return

    def submit_transaction(self,
                           payee: str,
                           amount: float
                           ) -> None:
        """
        Submits a transaction to the network. Adds it to the pending transactions list.
        :param payee: ip of the user receiving the money
        :param amount: amount of money transferred
        """

        if self.authenticated:

            # Required to be authenticated to submit a transaction

            if payee in self.nodes:

                # Payee is valid
                transaction: Transaction = Transaction(self.transaction_idx,
                                                       self.ip,
                                                       payee,
                                                       amount,
                                                       self.ledger)  # Exception raised if amount > balance
                with Lock():

                    self.ledger = transaction.ledger  # Updating the ledger
                    self.pending_transactions.append(transaction)

                # TODO: send transaction

                logging.info(self.pending_transactions)

            else:

                # Invalid payee
                raise TransactionNotValidException(nodes=self.nodes)

        else:

            message: str = 'Not authenticated on the network. Cannot submit transaction.'
            raise TransactionNotValidException(message=message)

    # ----------------------------------------------------- RUN ----------------------------------------------------- #

    def run(self) -> None:
        """
        Main method of the Node thread :
            1. tries to be authenticated on the network by the authentication center
            2. starts the server
            3. starts the mining
        """

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ AUTHENTICATION ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #

        with socket() as auth_client:

            # Creating a socket with default mode: IPv4/TCP
            is_bound = False
            auth_server_address = (self.authenticate_ip,
                                   self.server_port)
            while not is_bound:

                try:
                    auth_client.bind((self.ip, 0))  # OS takes care of free port allocation
                    auth_client.connect(auth_server_address)
                    is_bound = True

                except OSError:
                    logging.info("Server at {}:{} cannot be reached".format(self.authenticate_ip,
                                                                                self.server_port))
                    return

            while not self.authenticated:
                # Trying to be authenticated on the network
                self.__authenticate(auth_client)

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ SERVER ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #

        # Creating and starting the server thread
        server_thread = Thread(target=self.__serve_forever)
        with Lock():
            self.is_serving = True

        server_thread.start()

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ MINING ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #

        # Creating and starting the thread
        mining_thread = Thread(target=self.__mine)
        with Lock():
            self.is_mining = True

        mining_thread.start()
