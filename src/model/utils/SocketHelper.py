# !/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
This module contains all the functions helping with the operation of sockets
"""

# ----------------------------------------------------- IMPORTS ----------------------------------------------------- #

from socket import socket
from src import Bitcop, BitcopAuthenticate, BitcopTransaction
from sys import byteorder


__date__ = "10.12.2018"


# ---------------------------------------------------- FUNCTIONS ---------------------------------------------------- #

def send(sock: socket,
         request: Bitcop
         ) -> None:
    """
    Function used to send the data in request through the socket snd_socket
    Credit: https://docs.python.org/3/howto/sockets.html
    :param sock: socket used to send the data
    :param request: data to be sent
    """

    data = bytes(request)
    length = len(data)
    total_sent = 0

    while total_sent < length:

        sent = sock.send(data)  # sent saves the number of bytes sent
        if sent == 0:

            raise RuntimeError("Socket connection broken in send")

        total_sent += sent


def receive(sock: socket
            ) -> Bitcop:
    """
    Function used to get the data received through the socket rcv_socket
    Credit: https://docs.python.org/3/howto/sockets.html
    :param sock: socket from which the data is received
    :return: Bitcop message containing the information
    """

    # Retrieving the bytes stream

    chunks = []
    bytes_rcvd = 0
    number_of_first_bytes = Bitcop.NUMBER_BYTES_LENGTH
    first_chunk = sock.recv(number_of_first_bytes)
    bytes_rcvd += number_of_first_bytes
    chunks.append(first_chunk)
    length = int.from_bytes(first_chunk, byteorder)

    while bytes_rcvd < length:

        chunk = sock.recv(min(length - bytes_rcvd, 1024))
        if chunk == b'':

            raise RuntimeError("Socket connection broken in receive")

        chunks.append(chunk)
        bytes_rcvd += len(chunk)

    data = b''.join(chunks)

    # Parsing the Bitcop code of the message

    code_bytes = data[Bitcop.NUMBER_BYTES_LENGTH:
                      Bitcop.NUMBER_BYTES_LENGTH + Bitcop.NUMBER_BYTES_CODE]
    code = int.from_bytes(code_bytes, byteorder)

    if code // 10 == 1:

        # Authenticate message
        return BitcopAuthenticate(data_rcv=data)

    elif code // 10 == 2:

        # Transaction message
        return BitcopTransaction(data_rcv=data)
