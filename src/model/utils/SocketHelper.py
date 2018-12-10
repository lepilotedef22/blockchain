# !/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
This module contains all the functions helping with the operation of sockets
"""

# ----------------------------------------------------- IMPORTS ----------------------------------------------------- #

# Typing
from typing import Tuple

from socket import socket
from src import Bitcop


# ---------------------------------------------------- FUNCTIONS ---------------------------------------------------- #

# TODO : implement send and receive

def send(snd_socket: socket,
         rcv_address: Tuple[str, int],
         request: Bitcop
         ) -> None:
    """

    :param snd_socket:
    :param rcv_address:
    :param request:
    """


def receive(rcv_socket: socket
            ) -> Bitcop:
    """

    :param rcv_socket:
    :return:
    """
