# !/usr/bin/env python3
# -*- coding: utf-! -*-

# ----------------------------------------------------- IMPORTS ----------------------------------------------------- #

# Typing
from typing import Optional, Union, Tuple, Dict

from src import Bitcop, CodeNotValidException, parse_bytes_stream_from_message
from sys import byteorder


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
                 data: Optional[Union[str, int, Tuple[str, hash]]] = "ok",
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
                                                         Bitcop.HEADER,
                                                         Bitcop.NUMBER_BYTES_LENGTH,
                                                         Bitcop.NUMBER_BYTES_CODE)

            code = parsed_msg['code']

            if code not in Bitcop.AUTH:

                # Invalid code for Authentication
                raise CodeNotValidException(code=code, valid_codes=Bitcop.AUTH)

            super().__init__(code, data_rcv)

            if code == Bitcop.AUTH_RESP:

                # Response in the challenge-response scheme
                self.data = tuple(parsed_msg['data'].split(','))

            elif code == Bitcop.AUTH_CHAL:

                # Challenge in the challenge-response scheme
                self.data = int.from_bytes(parsed_msg['data'].encode('latin-1'), byteorder)

            else:

                self.data = parsed_msg['data']

    # --------------------------------------------------- METHODS --------------------------------------------------- #

    def __bytes__(self) -> bytes:

        """
        Returns the message in a byte form, ready to be sent
        :return: a byte stream to be sent
        """

        if self.data_rcv is None:

            # New message to be sent
            if self.code == Bitcop.AUTH_RESP:

                # Message is a response in the challenge-response scheme
                data_str = "{0},{1}".format(self.data[0], self.data[1].digest())
                data = data_str.encode('latin-1')

            elif self.code == Bitcop.AUTH_CHAL:

                # Message is a challenge in the challenge-response scheme
                data = self.data.to_bytes(Bitcop.NUMBER_BYTES_NONCE, byteorder)

            else:

                # Any other kind of authenticate message
                data = self.data.encode('latin-1')

            length = len(Bitcop.HEADER) + Bitcop.NUMBER_BYTES_LENGTH + Bitcop.NUMBER_BYTES_CODE + len(data)
            length_bytes = length.to_bytes(Bitcop.NUMBER_BYTES_LENGTH, byteorder)
            code_bytes = self.code.to_bytes(Bitcop.NUMBER_BYTES_CODE, byteorder)

            return Bitcop.HEADER.encode('latin-1') + length_bytes + code_bytes + data

        else:

            return self.data_rcv

    def get_request(self) -> Dict:

        """
        Returns a dictionary containing the information of the message
        :return: dictionary with the information in the message : {"code": code, "data": data}
        """

        return {'code': self.code,
                'data': self.data}
