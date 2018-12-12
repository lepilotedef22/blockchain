# !/usr/bin/env python3
# -*- coding: utf-8 -*-

# ----------------------------------------------------- IMPORTS ----------------------------------------------------- #

from threading import Thread

__date__ = "12.12.2018"


class Authenticate(Thread):

    """
    This class handles the authentication of the nodes on the Bitcom network. The authentication process is based on the
    challenge-response scheme : 1) node requests a authentication by sending its user_name
                                2) server responds with a nonce (coded on Bitcop.NUMBER_OF_BYTES bytes)
                                3) node responds with (user_name, sha256(nonce|secret)), secret being the shared secret
                                4) server responds with OK
    At any time, the communication can be stopped using the ABORT message
    """

    # ------------------------------------------------- CONSTRUCTOR ------------------------------------------------- #

    def __init__(self) -> None:

        """
        Constructor of the authenticate server
        """
        super().__init__()

    # --------------------------------------------------- METHODS --------------------------------------------------- #


