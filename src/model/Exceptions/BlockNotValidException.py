# !/usr/bin/env python3
# -*- coding: utf-8 -*-

# ----------------------------------------------------- IMPORTS ----------------------------------------------------- #

from typing import Optional


__date__ = "03.12.2018"


class BlockNotValidException(Exception):
    """
    This exception is raised when a block is invalid
    """

    def __init__(self,
                 computed_hash: Optional[str] = None,
                 given_hash: Optional[str] = None,
                 message: Optional[str] = None
                 ) -> None:
        """
        Constructor of the BlockNotValidException
        :param computed_hash: Hash computed by the node receiving the block
        :param given_hash: Hash received by the node receiving the block
        :param message: message to be passed to the exception
        """

        if computed_hash is not None and given_hash is not None:

            # Message is assumed to be None
            message: str = "Block is not valid.\nReceived hash: {}\nComputed hash: {}".format(given_hash,
                                                                                              computed_hash)

        super().__init__(message)
        self.message = message
