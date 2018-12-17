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
                 n: Node
                 ) -> None:
        """
        Constructor of the NodeShell
        :param n: node controlled by this NodeShell
        """

        super().__init__('tab',
                         None,
                         None)
        self.node = n
        self.intro = (
            "\n--------------------------------------------------------------------------------\n"
            "------------------------------------ BITCOM ------------------------------------\n"
            "--------------------------------------------------------------------------------"
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
        logging.info('Node is alive: {}'.format(node.is_alive()))

    def do_pay(self, arg) -> None:
        """
        Sends money to another user.
        usage: pay [payee ip] [amount]
        """

        pass

    def do_status(self, arg) -> None:
        """
        Display the authentication status.
        Display the balance (in BTM).
        """

        if len(arg) != 0:

            print("do_status() takes 0 positional argument but {} were given".format(len(arg)))

        else:

            auth_status = self.node.authenticated

            if auth_status:

                print("Node is authenticated on the BITCOM network.")
                print("Balance: {} BTM".format(self.node.balance))

            else:

                print("Node is not authenticated on the BITCOM network.")
                print("Please relaunch the program...")

    def do_transactions(self, arg) -> None:
        """
         Display transactions.
        """

        pass

    def do_exit(self, arg) -> bool:
        """
        Exit the program. (^D)
        """

        return True

    do_EOF = do_exit


# ------------------------------------------------------- MAIN ------------------------------------------------------- #


if __name__ == "__main__":

    # Args parsing (credit: https://docs.python.org/fr/3/howto/argparse.html)

    parser = ArgumentParser(
        description='User interface for the BITCOM network'
    )

    parser.add_argument(
                        'node_idx',
                        action='store',
                        help='Index of the node',
                        type=int
    )

    parser.add_argument(
                        '--log',
                        action='store',
                        help='Logger level',
                        default='warning',
                        choices=[
                            'debug',
                            'info',
                            'warning',
                            'error',
                            'critical'
                        ])

    args = vars(parser.parse_args())

    # Logging (credit: https://docs.python.org/3/howto/logging.html)

    numeric_level = getattr(logging, args['log'].upper(), None)
    logging.basicConfig(format='%(levelname)s:%(message)s',
                        level=numeric_level)

    # Starting node and node shell

    node_idx = args['node_idx']
    node = Node(node_idx)
    node.start()
    shell = NodeShell(node)
    shell.cmdloop()
    print("Program ended.")
