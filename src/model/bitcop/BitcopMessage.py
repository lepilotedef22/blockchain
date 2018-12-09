# !/usr/bin/env python3
# -*- coding: utf-8 -*-

# ----------------------------------------------------- IMPORTS ----------------------------------------------------- #

# Typing
from typing import Optional


__date__ = "09.12.2018"


class BitcopMessage:

    """
    Super class dealing with the messages used to communicate in the Bitcop protocol. It possesses class constants
    relative to each type of message supported by the protocol. It will be inherited to differentiate different kinds of
    messages.
    """

    # ---------------------------------------------- PROTOCOL CONSTANTS ---------------------------------------------- #

    DEFAULT = 0  # Message is default
    AUTH = 1  # Message is authenticate
    # TODO : add other features supported by the protocol

    # ------------------------------------------------- CONSTRUCTOR ------------------------------------------------- #

    def __init__(self,
                 data_rcv: Optional[bytes] = None) -> None:

        """
        Constructor of the class BitcopMessage
        In the subclasses, type and data need to be added
        :param data_rcv: stream of data bytes received that will be parsed to construct the object. None if the object
            is being created to send a new message.
        """

        self.data_rcv = data_rcv
