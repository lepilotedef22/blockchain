# !/usr/bin/env python3
# -*- coding: utf-8 -*-

# ----------------------------------------------------- IMPORTS ----------------------------------------------------- #

from src import Node, Authenticate


__date__ = "14.12.2018"


class Launcher:
    """
    This class starts the nodes and the authenticate center
    """

    # ------------------------------------------------- CONSTRUCTOR ------------------------------------------------- #

    def __init__(self) -> None:
        """
        Constructor of the launcher
        """

        self.nodes = [Node(i) for i in range(1, 7)]
        self.auth = Authenticate()


if __name__ == "__main__":

    launcher = Launcher()
    launcher.auth.start()
    for node in launcher.nodes:

        node.start()
