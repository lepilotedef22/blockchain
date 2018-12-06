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

from threading import Thread
import _thread
from socket import socket
from sys import byteorder
from src.model import Constants
from os import urandom
from re import sub
from hashlib import sha256


class Authenticate(Thread):

    """
    This class is responsible for the authenticate server used to validate the nodes on the network
    """

    # ------------------------------------------------- CONSTRUCTOR ------------------------------------------------- #

    def __init__(self) -> None:

        """
        Constructor of the authenticate server
        """

        super().__init__()
        self.ip = "127.0.0.10"  # As defined in the assignment
        self.port = 4242
        self.socket = socket()  # AF_INET and SOCK_STREAM are default values
        self.socket.bind((self.ip, self.port))
        self.socket.listen(5)

    # --------------------------------------------------- METHODS --------------------------------------------------- #

    @staticmethod
    def receive(client_socket, protocol=None, **kwargs) -> str:
        if protocol is not None:

            # bi-directional communication

            protocol(kwargs)

        else:

            # uni-directional communication

            chunks = []
            bytes_received = 0
            number_length_coding_bytes = 2
            length_coding_bytes = int.from_bytes(client_socket.recv(number_length_coding_bytes), byteorder)
            max_length = length_coding_bytes
            bytes_received += number_length_coding_bytes

            while bytes_received < max_length:

                chunk = client_socket.recv(min(max_length - bytes_received, 1024))  # 4096 is arbitrary

                if chunk == b"":
                    raise RuntimeError("Socket connection broken")

                chunks.append(chunk)
                bytes_received += len(chunk)

            return b"".join(chunks).decode("utf-8")

    def onNewClient(self, client_socket, addr):
        username = ""
        password = "1234"
        nonce = "abc"
        while True:
            msg = self.receive(client_socket)
            if msg == Constants.AUTH_MSG:
                print("new registration received")
                # nonce = urandom(8) # Remove when communication is bidirectional
                password = sha256((nonce+password).encode('utf-8')).hexdigest()
                # TODO send nonce to node
            elif "username:" in msg:
                username = sub("username:", "", msg)
                print(username)
            elif "password:" in msg:
                password_recvd = sub("password:", "", msg)
                if password_recvd == password:
                    print("correct password")
                else:
                    print("wrong password")
            else:
                print(addr, ' >> ', msg)

    def run(self) -> None:

        """
        Overriding the run method of threading. Main loop executed to intercept the authentication requests from
        the nodes and to manage them.
        """
        print("Server started")

        while True:
            c, addr = self.socket.accept()
            _thread.start_new_thread(self.onNewClient, (c, addr))



