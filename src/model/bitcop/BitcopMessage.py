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

    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ CODES ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #

    DEFAULT = 0  # Message is default

    # Authentication

    AUTH_REQ = 10  # Message is authenticate request
    AUTH_CHAL = 11  # Message is authenticate challenge
    AUTH_RESP = 12  # Message is authenticate response
    AUTH_OK = 13  # Message is authenticate OK

    AUTH = [AUTH_REQ, AUTH_CHAL, AUTH_RESP, AUTH_OK]

    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ CONSTANTS ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #

    NUMBER_BYTES_LENGTH = 2  # Number of bytes used to represent the length of the messages
    NUMBER_BYTES_CODE = 2  # Number of bytes used to represent the code

    # ------------------------------------------------- CONSTRUCTOR ------------------------------------------------- #

    def __init__(self,
                 code: int,
                 data_rcv: Optional[bytes] = None
                 ) -> None:

        """
        Constructor of the class BitcopMessage
        In the subclasses, data needs to be added
        :param code: integer code of the message
        :param data_rcv: stream of data bytes received that will be parsed to construct the object. None if the object
            is being created to send a new message.
        """

        self.code = code
        self.data_rcv = data_rcv
