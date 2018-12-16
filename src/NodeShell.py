# !/usr/bin/env python3
# -*- coding: utf-8 -*-

# ----------------------------------------------------- IMPORTS ----------------------------------------------------- #

from src import Node
from cmd import Cmd
import logging
from argparse import ArgumentParser


__date__ = "16.12.2018"


class NodeShell(Cmd):
    """
    This class is used as a shell UI. It inherits the super class Cmd to use the features of a command line interface.
    """

    # ------------------------------------------------- CONSTRUCTOR ------------------------------------------------- #

    def __init__(self,
                 node: Node
                 ) -> None:
        """
        Constructor of the NodeShell
        :param node: node controlled by this NodeShell
        """

        super().__init__('tab',
                         None,
                         None)
        self.node = node
        self.intro = (
            "\n--------------------------------------------------------\n"
            "------------------------ BITCOM ------------------------\n"
            "--------------------------------------------------------"
        )
        self.prompt = '>>>'
        self.ruler = ''
        self.doc_header = 'Available commands: '

    # --------------------------------------------------- METHODS --------------------------------------------------- #

    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ METHODS CALLED BY SHELL ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #

    def preloop(self) -> None:
        """
        Method run before main cmd loop
        """

        print(self.intro)  # Printing program title
        self.do_help('')  # Printing available commands
        self.intro = ''

    def postloop(self) -> None:
        """
        Method run after main cmd loop
        """

        print("\nNode stopping...")
        self.node.stop()
        print("Node stopped.\n")

    def do_pay(self, args) -> None:
        """
        Sends money to another user
        usage: pay [payee] [amount]
        """

        pass

    def do_status(self, args) -> None:
        """
        Display the balance (in BTM)
        """

        if len(args) != 0:

            print("do_status() takes 0 positional argument but {} were given".format(len(args)))

        else:

            print("Balance: {} BTM".format(self.node.balance))

    def do_transactions(self, args) -> None:
        """
         Display transactions
        """

        pass

    def do_exit(self, args) -> bool:
        """
        Exit the program
        """

        return True


# ------------------------------------------------------- MAIN ------------------------------------------------------- #


if __name__ == "__main__":

    node = Node(1)
    node.start()
    shell = NodeShell(node)
    shell.cmdloop()
    print("Program ended.")
