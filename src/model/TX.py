# !/usr/bin/env python3
# coding: utf-8

"""
This module deals with the transmitter super class. This class needs to be able to send a message to another host. And
it should also be able to have a bi-directional communication with server according to a given protocol. It is used for
the client-side of the architecture
"""

__author__ = "Denis Verstraeten & Arthur Van Heirstraeten"
__date__ = "27.11.2018"

# ----------------------------------------------------- IMPORTS ----------------------------------------------------- #

from socket import socket
from src.model.ComHelper import format_message


class TX:

    # ------------------------------------------------- CONSTRUCTOR ------------------------------------------------- #

    def __init__(self, ip: int, port: int) -> None:

        """
        Constructor
        :param ip: ip address of the TX host
        :param port: port of the TX host
        """

        self.ip = ip
        self.port = port
        self.socket = socket()  # AF_INET and SOCK_STREAM are default values
        self.socket.bind((self.ip, self.port))

    # --------------------------------------------------- METHODS --------------------------------------------------- #

    def send(self, dest_ip: int, dest_port: int, msg: str, protocol: function=None, **kwargs) -> None:

        """
        Main method of the class. Sends the message msg to the remote host defined by (dest_ip, dest_port). Uses the
        function protocol if a bi-directional non-trivial communication needs to take place

        Credit : https://docs.python.org/3/howto/sockets.html

        :param protocol: protocol function be executed in the case of a bi-directional communication
        :param dest_ip: ip of the remote host
        :param dest_port: port of the remote host
        :param msg: string to be sent
        """

        self.socket.connect((dest_ip, dest_port))

        if protocol is not None:

            # bi-directional communication

            protocol(kwargs)

        else:

            # uni-directional communication

            number_length_coding_bytes = 2
            message = format_message(msg, number_length_coding_bytes)
            message_length = len(message)
            total_sent = 0

            while total_sent < message_length:

                sent = self.socket.send(message[total_sent:])

                if sent == 0:

                    raise RuntimeError("Socket connection broken")

                total_sent += sent

        self.socket.close()
