# !/usr/bin/env python3
# -*- coding: utf-! -*-

# ----------------------------------------------------- IMPORTS ----------------------------------------------------- #

# Typing
from typing import Optional, Union, Tuple

from src import BitcopMessage, CodeNotValidException
from hashlib import sha256


__date__ = "10.12.2018"


class BitcopMessageAuthenticate(BitcopMessage):

    """
    Class dealing with authentication messages
    """

    # ------------------------------------------------- CONSTRUCTOR ------------------------------------------------- #

    def __init__(self,
                 code: Optional[int] = None,
                 data: Optional[Union[str, int, Tuple[str, hash]]] = "ok",
                 data_rcv: Optional[bytes] = None
                 ) -> None:

        """
        Constructor of the BitcopMessageAuthenticate
        :param code: code of the message sent in the Bitcop protocol, None if the object is based on an incoming stream
            of bytes
        :param data: data transmitted, None if the object is based on an incoming stream of bytes
        :param data_rcv: bytes of the received message, None if the object is based on a new message to be sent
        """

        if data_rcv is None:

            # Message created for a TX request -> code and data are assumed to be not None
            if code not in BitcopMessage.AUTH:

                # Invalid code for Authentication
                raise CodeNotValidException(code=code, valid_codes=BitcopMessage.AUTH)

            super().__init__(code, data_rcv)
            self.data = data

        else:

            # Message created from a RX request -> code and data are assumed to be None




