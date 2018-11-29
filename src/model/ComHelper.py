# !/usr/bin/env python3
# -*- coding: utf-8 -*-

__date__ = "27.11.2018"

"""
This module contains the helping functions used to simplify the communication classes
"""

# ----------------------------------------------------- IMPORTS ----------------------------------------------------- #

from sys import byteorder

# ---------------------------------------------------- FUNCTIONS ---------------------------------------------------- #


def format_message(msg: str, num_bytes: int) -> bytes:

    """
    Formats the message to be sent (msg) correctly by adding its length on the first num_bytes bytes
    :param msg: string message to be sent
    :param num_bytes: number of bytes on which the length of the message is coded
    :return: the bytes message sent by the socket
    """

    msg_length = len(msg) + num_bytes
    length_in_bytes = msg_length.to_bytes(num_bytes, byteorder)
    return length_in_bytes + str.encode(msg)
