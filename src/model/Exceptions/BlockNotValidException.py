# !/usr/bin/env python3
# -*- coding: utf-8 -*-

__date__ = "03.12.2018"

from typing import Optional

class BlockNotValidException(Exception):

    """
    This exception is raised when a block is invalid
    """

    def __init__(self,
                 hash_computed: Optional[bytes] = None,
                 given_hash: Optional[bytes] = None,
                 message: Optional[str] = None
                 ) -> None:
        """

        :param hash_computed: Hash computed by the node receiving the block
        :param given_hash: Hash received by the node receiving the block
        :param message: message o be passed to the exception
        """


        if hash_computed is not None and given_hash is not None:

            # If message is None, the passed args are spent and available
            message: str = "Block not valid.\nComputed hash: {} BTM\nGiven hash: {} BTM".format(hash_computed,
                                                                                                given_hash)


        """
        Constructor of the BlockNotValidException
        :param message: optional message to be passed when raising the exception
        """

        super().__init__(message)
        self.message = message
