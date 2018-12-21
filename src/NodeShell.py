# !/usr/bin/env python3
# -*- coding: utf-8 -*-

# ----------------------------------------------------- IMPORTS ----------------------------------------------------- #

from src import Node, TransactionNotValidException, Transaction
from cmd import Cmd
import logging
from argparse import ArgumentParser
from time import strftime, localtime


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
        print("\nEnter 'help' to see the commands available\n")
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
        """

        # Arg parsing

        pay_parser = ArgumentParser(
            prog="pay",
            description="Sends money to another user."
        )

        pay_parser.add_argument(
            'ip',
            action='store',
            help='IP address of the user receiving the money',
            type=str
        )

        pay_parser.add_argument(
            'amount',
            action='store',
            help='Amount of money you want to send (in BTM)',
            type=float
        )

        try:

            # Handling wring type of args passed
            pay_args = vars(pay_parser.parse_args(arg.split()))

        except SystemExit:

            return

        payee = pay_args['ip']
        amount = pay_args['amount']
        print("{}% transaction fees.".format(Transaction.TRANSACTION_FEES * 100))
        print("It will cost you {:.2f} BTM".format(amount + Transaction.TRANSACTION_FEES * amount))
        cond = input("Do you agree? Y(es)\n")
        if cond.upper() == "Y" or cond.upper() == "YES":

            try:

                self.node.submit_transaction(payee, amount)
                print("Transaction submitted to the network.")

            except TransactionNotValidException as e:

                logging.warning(e.message)

        else:
            print("Transaction aborted...")

    def do_status(self, arg) -> None:
        """
        Display the authentication status.
        Display the IP address.
        Display the balance (in BTM).
        Display the last block hash an index.
        Display the number of pending transactions.
        """

        # Arg parsing

        status_parser = ArgumentParser(
            prog='status',
            description="""Display the authentication status, IP and current balance (in BTM), last block hash 
            and index, and the number of pending transactions."""
        )

        try:

            status_parser.parse_args(arg.split())

        except SystemExit:

            return

        auth_status = self.node.authenticated

        if auth_status:

            print("Node is authenticated on the BITCOM network.")
            print("IP: {}".format(self.node.ip))
            print("Balance: {:.2f} BTM".format(self.node.ledger[self.node.ip]))

            if self.node.blockchain.get_last_block() is not None:

                print("Last block: \n\tNumber: {}\n\tHash: {}".format(self.node.blockchain.get_last_block().idx,
                                                                      self.node.blockchain.get_last_block().hash))

            else:

                print("Last block: \n\tNumber: No block yet\n\tHash: ---")

            print("Number of pending transactions: {}".format(len(self.node.pending_transactions)))

        else:

            print("Node is not authenticated on the BITCOM network.")
            print("Please relaunch the program...")

    def do_transactions(self, arg) -> None:
        """
         Display transactions.
        """

        # Args parsing

        transaction_parser = ArgumentParser(
            prog='transactions',
            description="Shows the transaction history",
            epilog="[date]: [in/out] [payer] -> [payee] [amount] BTM: [balance] BTM"
        )

        try:

            transaction_parser.parse_args(arg.split())

        except SystemExit:

            return

        disp_pending_transactions = []  # List of the transactions to be displayed in the pending transactions
        for transaction in self.node.pending_transactions:

            if self.node.ip == transaction.payer:

                date: str = strftime("%a, %d %b %Y %H:%M:%S", localtime(transaction.timestamp))
                disp_pending_transactions.append("{}: [-] {} -> {} {:.2f} BTM: {:.2f} BTM".format(
                    date,
                    transaction.payer,
                    transaction.payee,
                    transaction.amount,
                    transaction.ledger[self.node.ip]
                ))

            elif self.node.ip == transaction.payee:

                amount = transaction.amount / (1 + Transaction.TRANSACTION_FEES)
                date: str = strftime("%a, %d %b %Y %H:%M:%S", localtime(transaction.timestamp))
                disp_pending_transactions.append("{}: [-] {} -> {} {:.2f} BTM: {:.2f} BTM".format(
                    date,
                    transaction.payer,
                    transaction.payee,
                    amount,
                    transaction.ledger[self.node.ip]
                ))

        disp_pending_transactions.reverse()
        if len(disp_pending_transactions) == 0:

            print("No pending transaction")

        else:

            print("Pending transactions:")

            for transaction in disp_pending_transactions:

                print(transaction)

        if len(self.node.blockchain.get_transactions(self.node.ip)) == 0:

            print("No transaction in blocks.")

        else:

            print("Transactions saved in blocks:")

            for transaction in self.node.blockchain.get_transactions(self.node.ip):

                print(transaction)

    def do_exit(self, arg) -> bool:
        """
        Exit the program. (^D)
        """

        exit_parser = ArgumentParser(
            prog="exit",
            description="Exits the program..."
        )

        try:

            exit_parser.parse_args(arg.split())

        except SystemExit:

            return False

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
