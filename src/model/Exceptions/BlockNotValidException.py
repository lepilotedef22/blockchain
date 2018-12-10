# !/usr/bin/env python3
# -*- coding: utf-8 -*-

__date__ = "03.12.2018"


class BlockNotValidException(Exception):

    """
    This exception is raised when a block is invalid
    """

    def __init__(self, message: str = None) -> None:

        """
        Constructor of the BlockNotValidException
        :param message: optional message to be passed when raising the exception
        """

        super().__init__(message)
        self.message = message
