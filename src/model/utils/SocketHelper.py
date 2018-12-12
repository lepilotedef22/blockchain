# !/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
This module contains all the functions helping with the operation of sockets
"""

# ----------------------------------------------------- IMPORTS ----------------------------------------------------- #

from socket import socket
from src import Bitcop, BitcopAuthenticate
from sys import byteorder


__date__ = "10.12.2018"


# ---------------------------------------------------- FUNCTIONS ---------------------------------------------------- #

def send(snd_socket: socket,
         request: Bitcop
         ) -> None:
    """
    Function used to send the data in request through the socket snd_socket
    Credit: https://docs.python.org/3/howto/sockets.html
    :param snd_socket: socket used to send the data
    :param request: data to be sent
    """

    data = bytes(request)
    length = len(data)
    total_sent = 0

    while total_sent < length:

        sent = snd_socket.send(data)  # sent saves the number of bytes sent
        if sent == 0:

            raise RuntimeError("Socket connection broken in send")

        total_sent += sent


def receive(rcv_socket: socket
            ) -> Bitcop:
    """
    Function used to get the data received through the socket rcv_socket
    Credit: https://docs.python.org/3/howto/sockets.html
    :param rcv_socket: socket from which the data is received
    :return: Bitcop message containing the information
    """

    # Retrieving the bytes stream

    chunks = []
    bytes_rcvd = 0
    number_of_first_bytes = len(Bitcop.HEADER) + Bitcop.NUMBER_BYTES_LENGTH
    first_chunk = rcv_socket.recv(number_of_first_bytes)
    bytes_rcvd += number_of_first_bytes
    chunks.append(first_chunk)
    length = int.from_bytes(first_chunk[len(Bitcop.HEADER):], byteorder)

    while bytes_rcvd < length:

        chunk = rcv_socket.recv(min(length - bytes_rcvd, 1024))
        if chunk == b'':

            raise RuntimeError("Socket connection broken in receive")

        chunks.append(chunk)
        bytes_rcvd += len(chunk)

    data = b''.join(chunks)

    # Parsing the Bitcop code of the message

    code_bytes = data[len(Bitcop.HEADER) + Bitcop.NUMBER_BYTES_LENGTH:
                      len(Bitcop.HEADER) + Bitcop.NUMBER_BYTES_LENGTH + Bitcop.NUMBER_BYTES_CODE]
    code = int.from_bytes(code_bytes, byteorder)

    if code // 10 == 1:

        # Authenticate message
        return BitcopAuthenticate(data_rcv=data)