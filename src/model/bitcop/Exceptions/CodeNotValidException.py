# !/usr/bin/env python3
# -*- coding: utf-8 -*-

# ----------------------------------------------------- IMPORTS ----------------------------------------------------- #

# Typing
from typing import Optional, List


__date__ = "10.12.2018"


class CodeNotValidException(Exception):

    """
    Exception raised when a message is created with a code that does not match its type
    """

    # ------------------------------------------------- CONSTRUCTOR ------------------------------------------------- #

    def __init__(self,
                 message: Optional[str] = None,
                 code: Optional[int] = None,
                 valid_codes: Optional[List[int]] = None
                 ) -> None:

        """
        Constructor of the CodeNotValidException
        :param message: optional personalised message to be passed when raising the exception
        :param code: erroneous code passed
        :param valid_codes: list of the valid codes for this class of message
        """

        if message is not None:

            super().__init__(message)
            self.message = message

        elif code is not None and valid_codes is not None:

            # Credit : https://stackoverflow.com/questions/7568627/using-python-string-formatting-with-lists
            formatted_list = ['{:>3}' for item in valid_codes]
            string_list = ','.join(formatted_list)
            codes_string = string_list.format(*valid_codes)
            message = "Code {0} does not belong to allowed AUTHENTICATION codes :{1}".format(code, codes_string)

            super().__init__(message)
            self.message = message
