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
    Bitcop protocol : Length | Code | Data
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

    AUTH: List[int] = [AUTH_REQ, AUTH_CHAL, AUTH_RESP, AUTH_OK]

    # Transaction

    TRAN_ID: int = 20  # Message transaction id
    TRAN_EX: int = 21  # Message is transaction exchange
    TRAN_NN: int = 22  # Message is transaction no-need

    TRAN: List[int] = [TRAN_ID, TRAN_EX, TRAN_NN]

    # Block

    BLOCK_ID: int = 30  # Message block id
    BLOCK_EX: int = 31  # Message is block exchange
    BLOCK_NN: int = 32  # Message is block no-need

    BLOCK: List[int] = [BLOCK_ID, BLOCK_EX]

    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ CONSTANTS ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #

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
        self.data = None

    # --------------------------------------------------- METHODS --------------------------------------------------- #

    def get_request(self) -> Dict:

        """
        Returns a dictionary containing the information of the message
        :return: dictionary with the information in the message : {"code": code, "data": data}
        """

        return {'code': self.code,
                'data': self.data}

    # ----------------------------------------------- ABSTRACT METHODS ----------------------------------------------- #

    @abstractmethod
    def __bytes__(self) -> bytes:
        """
        Translates the request into a byte stream. Needs to be implemented.
        :return: the byte stream
        """

        pass
