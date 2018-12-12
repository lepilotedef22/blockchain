# !/usr/bin/env python3
# -*- coding: utf-8 -*-

# ----------------------------------------------------- IMPORTS ----------------------------------------------------- #

# Typing
from typing import Optional, Dict, List

from abc import ABC, abstractmethod


__date__ = "09.12.2018"


class Bitcop(ABC):

    """
    Super class dealing with the messages used to communicate in the Bitcop protocol. It possesses class constants
    relative to each type of message supported by the protocol. It will be inherited to differentiate different kinds of
    messages. Terminology :  new message refers to an object containing the data of a message about meant to be sent in
    the near future. Byte stream refers to an object created based on a previously received message.
    Bitcop protocol : "header" = "bitcop" | Length | Code | Data
    The length of the messages are not hardcoded, the number of bytes on which the total length of the message and the
    code of the message are coded are class constants, and therefore not hardcoded either
    """

    # ---------------------------------------------- PROTOCOL CONSTANTS ---------------------------------------------- #

    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ CODES ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #

    DEFAULT: int = 0  # Message is default

    # Authentication

    AUTH_REQ: int = 10  # Message is authenticate request
    AUTH_CHAL: int = 11  # Message is authenticate challenge
    AUTH_RESP: int = 12  # Message is authenticate response
    AUTH_OK: int = 13  # Message is authenticate OK
    AUTH_ABORT: int = 14  # Message is abort authentication

    AUTH: List[int] = [AUTH_REQ, AUTH_CHAL, AUTH_RESP, AUTH_OK, AUTH_ABORT]

    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ CONSTANTS ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #

    HEADER: str = "bitcop"  # Header of the protocol
    NUMBER_BYTES_LENGTH: int = 2  # Number of bytes used to represent the length of the messages
    NUMBER_BYTES_CODE: int = 2  # Number of bytes used to represent the code
    NUMBER_BYTES_NONCE: int = 16  # Number of bytes of the nonce

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

        self.code: int = code
        self.data_rcv: bytes = data_rcv

    # ----------------------------------------------- ABSTRACT METHODS ----------------------------------------------- #

    @abstractmethod
    def __bytes__(self) -> bytes:
        """
        Translates the request into a byte stream. Needs to be implemented.
        :return: the byte stream
        """

        pass

    @abstractmethod
    def get_request(self) -> Dict:
        """
        Get the request information in a dictionary. Needs to be implemented.
        :return: dictionary containing the information of the message
        """

        pass
