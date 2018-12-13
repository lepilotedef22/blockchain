# !/usr/bin/env python3
# -*- coding: utf-! -*-

# ----------------------------------------------------- IMPORTS ----------------------------------------------------- #

# Typing
from typing import Optional, Union, List, Dict

from src import Bitcop, CodeNotValidException, parse_bytes_stream_from_message
from sys import byteorder
from json import dumps, loads


__date__ = "10.12.2018"


class BitcopAuthenticate(Bitcop):

    """
    Class dealing with authentication messages. Codes : 10 : authentication request
                                                        11 : challenge
                                                        12 : response
                                                        13 : authenticated
    """

    # ------------------------------------------------- CONSTRUCTOR ------------------------------------------------- #

    def __init__(self,
                 code: Optional[int] = None,
                 data: Optional[Union[str, int, List[str, str]]] = "ok",
                 data_rcv: Optional[bytes] = None
                 ) -> None:

        """
        Constructor of the BitcopAuthenticate
        :param code: code of the message sent in the Bitcop protocol, None if the object is based on an incoming stream
            of bytes
        :param data: data transmitted, None if the object is based on an incoming stream of bytes
        :param data_rcv: bytes of the received message, None if the object is based on a new message to be sent
        """

        if data_rcv is None:

            # Message created for a TX request -> code and data are assumed to be not None
            if code not in Bitcop.AUTH:

                # Invalid code for Authentication
                raise CodeNotValidException(code=code, valid_codes=Bitcop.AUTH)

            super().__init__(code, data_rcv)
            self.data = data

        else:

            # Message created from a RX request -> code and data are assumed to be None
            parsed_msg = parse_bytes_stream_from_message(data_rcv,
                                                         Bitcop.NUMBER_BYTES_LENGTH,
                                                         Bitcop.NUMBER_BYTES_CODE)

            code = parsed_msg['code']

            if code not in Bitcop.AUTH:

                # Invalid code for Authentication
                raise CodeNotValidException(code=code, valid_codes=Bitcop.AUTH)

            super().__init__(code, data_rcv)

            self.data = loads(parsed_msg['data'])

    # --------------------------------------------------- METHODS --------------------------------------------------- #

    def __bytes__(self) -> bytes:

        """
        Returns the message in a byte form, ready to be sent
        :return: a byte stream to be sent
        """

        if self.data_rcv is None:

            # New message to be sent
            data = dumps(self.data).encode('utf-8')
            length = Bitcop.NUMBER_BYTES_LENGTH + Bitcop.NUMBER_BYTES_CODE + len(data)
            length_bytes = length.to_bytes(Bitcop.NUMBER_BYTES_LENGTH, byteorder)
            code_bytes = self.code.to_bytes(Bitcop.NUMBER_BYTES_CODE, byteorder)

            return length_bytes + code_bytes + data

        else:

            return self.data_rcv

    def get_request(self) -> Dict:

        """
        Returns a dictionary containing the information of the message
        :return: dictionary with the information in the message : {"code": code, "data": data}
        """

        return {'code': self.code,
                'data': self.data}
