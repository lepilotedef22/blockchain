# !/usr/bin/env python3
# -*- coding: utf-8 -*-

#  IMPORTS  #

from src import Bitcop, CodeNotValidException, Block, parse_bytes_stream_from_message
from typing import Optional, Union
from sys import byteorder
from json import loads, dumps


__date__ = "17.12.2018"


class BitcopBlock(Bitcop):
    """
    Class dealing with transaction messages. Codes: 30: BLOCK_ID: block id
                                                    31: BLOCK_EX: block exchange
                                                    32: BLOCK_NN: block not needed
    """

    # ------------------------------------------------- CONSTRUCTOR ------------------------------------------------- #

    def __init__(self,
                 code: Optional[int] = None,
                 data: Optional[Union[int, str, Block]] = None,
                 data_rcv: Optional[bytes] = None
                 ) -> None:
        """
        Constructor of the BitcopBlock
        :param code: code of the message sent in the Bitcop protocol, None if the object is based on an incoming stream
            of bytes
        :param data: data transmitted, None if the object is based on an incoming stream of bytes
        :param data_rcv: bytes of the received message, None if the object is based on a new message to be sent
        """

        if data_rcv is None:

            # Message created for a TX request -> code and data are assumed to be not None
            if code not in Bitcop.BLOCK:
                # Invalid code for Transaction
                raise CodeNotValidException(code=code, valid_codes=Bitcop.BLOCK)

            super().__init__(code, data_rcv)
            self.data = data

        else:

            # Message created from a RX request -> code and data are assumed to be None
            parsed_msg = parse_bytes_stream_from_message(data_rcv,
                                                         Bitcop.NUMBER_BYTES_LENGTH,
                                                         Bitcop.NUMBER_BYTES_CODE)
            code = parsed_msg['code']
            if code not in Bitcop.BLOCK:

                # Invalid code for Block
                raise CodeNotValidException(code=code, valid_codes=Bitcop.BLOCK)

            elif code == Bitcop.BLOCK_ID:

                # Data is a int
                data = int.from_bytes(parsed_msg['data'], byteorder)

            elif code == Bitcop.BLOCK_EX:

                # Data is a json
                data = Block(block_json=loads(parsed_msg['data'].decode('utf-8')))

            elif code == Bitcop.BLOCK_NN:

                # Data is str
                data = parsed_msg['data'].decode('utf-8')

            super().__init__(code, data_rcv)
            self.data = data

    # --------------------------------------------------- METHODS --------------------------------------------------- #

    def __bytes__(self) -> bytes:

        """
        Returns the message in a byte form, ready to be sent
        :return: a byte stream to be sent
        """

        if self.data_rcv is None:

            # New message to be sent
            data = None
            if self.code == Bitcop.BLOCK_ID:

                # Data is a int
                data = self.data.to_bytes(Bitcop.NUMBER_BYTES_NONCE, byteorder)

            elif self.code == Bitcop.BLOCK_EX:

                # Data is a Block
                data = dumps(self.data.get_json()).encode('utf-8')

            elif self.code == Bitcop.BLOCK_NN:

                # Data is str
                data = self.data.encode('utf-8')

            length = Bitcop.NUMBER_BYTES_LENGTH + Bitcop.NUMBER_BYTES_CODE + len(data)
            length_bytes = length.to_bytes(Bitcop.NUMBER_BYTES_LENGTH, byteorder)
            code_bytes = self.code.to_bytes(Bitcop.NUMBER_BYTES_CODE, byteorder)

            return length_bytes + code_bytes + data

        else:

            return self.data_rcv
