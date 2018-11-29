# !/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
This module deals with the receiver super class. This class needs to be able to receive a message from another host. It
should also be able to have a bi-directional communication with a client according to a given protocol. It is used for
the server-side of the architecture
"""

__date__ = "27.11.2018"

# ----------------------------------------------------- IMPORTS ----------------------------------------------------- #

from socket import socket
from sys import byteorder


class RX:

    """
    This class is used as a RX for socket communication. It is supposed to be specialised through inheritance
    """

    # ------------------------------------------------- CONSTRUCTOR ------------------------------------------------- #

    def __init__(self, ip: str, port: int) -> None:

        """
        Constructor of the RX class
        :param ip: ip address of the RX host
        :param port: port of the RX host
        """

        self.ip = ip
        self.port = port
        self.socket = socket()  # AF_INET and SOCK_STREAM are default values
        self.socket.bind((self.ip, self.port))

    # --------------------------------------------------- METHODS --------------------------------------------------- #

    def receive(self, protocol=None, **kwargs) -> str:

        """
        Main method of the class. Listens for incoming messages sent by remote_hosts. Uses the function protocol if a
        bi-directional non-trivial communication needs to take place

        Credit : https://docs.python.org/3/howto/sockets.html

        :param protocol: protocol function be executed in the case of a bi-directional communication
        :return: the received message
        """

        self.socket.listen(5)  # listens for up to 5 connections
        client_socket, address = self.socket.accept()

        if protocol is not None:

            # bi-directional communication

            protocol(kwargs)

        else:

            # uni-directional communication

            chunks = []
            bytes_received = 0
            number_length_coding_bytes = 2
            length_coding_bytes = client_socket.recv(number_length_coding_bytes)
            max_length = int.from_bytes(length_coding_bytes, byteorder)
            bytes_received += length_coding_bytes

            while bytes_received < max_length:

                chunk = client_socket.recv(min(max_length - bytes_received, 4096))  # 4096 is arbitrary

                if chunk == b"":

                    raise RuntimeError("Socket connection broken")

                chunks.append(chunk)
                bytes_received += len(chunk)

            return b"".join(chunks).decode("utf-8")
