# !/usr/bin/env python3
# -*- coding: utf-8 -*-

#  IMPORTS  #

from src import Bitcop, CodeNotValidException, Transaction, parse_bytes_stream_from_message
from typing import Optional, Union
from sys import byteorder
from json import loads, dumps


__date__ = "17.12.2018"


class BitcopTransaction(Bitcop):
    """
    Class dealing with transaction messages. Codes: 20: TRAN_ID: transaction id
                                                    21: TRAN_NN: transaction no need
                                                    22: TRAN_EX: transaction exchange
    """

    # ------------------------------------------------- CONSTRUCTOR ------------------------------------------------- #

    def __init__(self,
                 code: Optional[int] = None,
                 data: Optional[Union[int, str, Transaction]] = None,
                 data_rcv: Optional[bytes] = None
                 ) -> None:
        """
        Constructor of the BitcopTransaction
        :param code: code of the message sent in the Bitcop protocol, None if the object is based on an incoming stream
            of bytes
        :param data: data transmitted, None if the object is based on an incoming stream of bytes
        :param data_rcv: bytes of the received message, None if the object is based on a new message to be sent
        """

        if data_rcv is None:

            # Message created for a TX request -> code and data are assumed to be not None
            if code not in Bitcop.TRAN:
                # Invalid code for Transaction
                raise CodeNotValidException(code=code, valid_codes=Bitcop.TRAN)

            super().__init__(code, data_rcv)
            self.data = data

        else:

            # Message created from a RX request -> code and data are assumed to be None
            parsed_msg = parse_bytes_stream_from_message(data_rcv,
                                                         Bitcop.NUMBER_BYTES_LENGTH,
                                                         Bitcop.NUMBER_BYTES_CODE)

            code = parsed_msg['code']

            if code not in Bitcop.TRAN:

                # Invalid code for Transaction
                raise CodeNotValidException(code=code, valid_codes=Bitcop.TRAN)

            elif code == Bitcop.TRAN_ID:

                # Data is a int
                data = int.from_bytes(parsed_msg['data'], byteorder)

            elif code == Bitcop.TRAN_NN:

                # Data is a string
                data = parsed_msg['data'].decode('utf-8')

            elif code == Bitcop.TRAN_EX:

                # Data is a json
                data = Transaction(transaction_json=loads(parsed_msg['data'].decode('utf-8')))

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
            if self.code == Bitcop.TRAN_ID:

                # Data is a int
                data = self.data.to_bytes(Bitcop.NUMBER_BYTES_NONCE, byteorder)

            elif self.code == Bitcop.TRAN_NN or self.code == Bitcop.TRAN_ABORT:

                # Data is a string
                data = self.data.encode('utf-8')

            elif self.code == Bitcop.TRAN_EX:

                # Data is a Transaction
                data_dict = {'idx': self.data.idx,
                             'payer': self.data.payer,
                             'payee': self.data.payee,
                             'amount': self.data.amount,
                             'ledger': self.data.ledger,
                             'timestamp': self.data.timestamp}
                data = dumps(data_dict).encode('utf-8')

            length = Bitcop.NUMBER_BYTES_LENGTH + Bitcop.NUMBER_BYTES_CODE + len(data)
            length_bytes = length.to_bytes(Bitcop.NUMBER_BYTES_LENGTH, byteorder)
            code_bytes = self.code.to_bytes(Bitcop.NUMBER_BYTES_CODE, byteorder)

            return length_bytes + code_bytes + data

        else:

            return self.data_rcv
