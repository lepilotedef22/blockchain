# !/usr/bin/env python3
# -*- coding: utf-! -*-

# ----------------------------------------------------- IMPORTS ----------------------------------------------------- #

from typing import List, Dict, Tuple, Union
from threading import Thread, Lock
from src import parse_config_node, Blockchain, Bitcop, BitcopAuthenticate, send, receive, Transaction, \
    TransactionNotValidException, BitcopTransaction, min_args, Block, BitcopBlock, BlockNotValidException
from socket import socket
from hashlib import sha256
from sys import byteorder
from time import sleep
import logging
from copy import deepcopy


__date__ = "07.12.2018"


class Node(Thread):
    """
    Class representing a node of the network.
    """

    # ------------------------------------------------- CONSTRUCTOR ------------------------------------------------- #

    def __init__(self,
                 node_idx: int
                 ) -> None:
        """
        Constructor of the Node class
        :param node_idx: index of the node used to find the config file to parse
        """

        super().__init__()

        # Parsing config files
        config = parse_config_node(node_idx)
        self.username: str = config['node']['username']
        self.ip: str = config['node']['ip_address']  # Alias loopback address (cf. assignment)
        self.authenticate_ip: str = config['registration']['ip_address']
        self.secret: str = config['registration']['secret']
        self.neighbours_ip: List[str] = config['neighbours']

        # Other attributes
        self.server_port: int = 5001  # Arbitrary, given in the assignment
        self.blockchain: Blockchain = Blockchain()
        self.authenticated: bool = False  # Authenticated to the network ?
        self.peers: List[str] = None  # IP of all the peers on the network
        self.is_listening = False  # Node IP is serving ?
        self.is_mining = False  # Node is mining ?
        self.transaction_idx: int = 0  # Index of the next transaction entering the node
        self.pending_transactions: List[Transaction] = []  # List of transactions waiting to be mined into a block
        self.ledger: Dict[str, float] = None  # Amount on the accounts of all the users {ip, balance}

    # --------------------------------------------------- METHODS --------------------------------------------------- #

    def stop(self) -> None:
        """
        Stops the threads
        """

        with Lock():

            # Shutting down the threads
            self.is_mining = False
            self.is_listening = False

            # Shutting down node listener (avoid being stuck in accept mode)
            with socket() as closing_socket:

                closing_socket.connect((self.ip, self.server_port))
                closing_socket.send(b'')

    def __handle_request(self,
                         peer_socket: socket,
                         peer_address: Tuple[Union[str, int]]
                         ) -> None:
        """
        Method running on its own thread to handle peer's requests
        :param peer_socket: socket to communicate with the peer
        :param peer_address: address (ip, port) of the peer
        """

        try:

            peer_request: Bitcop = receive(peer_socket)
            peer_request_code = peer_request.get_request()['code']
            logging.debug("__handle_request(): First request code: {} from peer at {}:{}".format(peer_request_code,
                                                                                                 peer_address[0],
                                                                                                 peer_address[1]))

            # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ TRANSACTION ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #

            if peer_request_code == Bitcop.TRAN_ID:

                # Peer transaction idx
                peer_transaction_idx = peer_request.get_request()['data']
                logging.debug("Peer transaction idx: {}".format(peer_transaction_idx))

                with Lock():

                    last_idx = self.transaction_idx

                logging.debug("Last transaction idx: {}".format(last_idx))

                if last_idx <= peer_transaction_idx:

                    # Node needs transaction(s) from peer
                    transaction_idx_message = BitcopTransaction(Bitcop.TRAN_ID,
                                                                last_idx)
                    logging.debug("Sending last transaction idx of node to peer")
                    send(peer_socket, transaction_idx_message)
                    logging.debug("Last transaction idx of node sent to peer")
                    for idx in range(last_idx, peer_transaction_idx + 1):

                        logging.debug("Receiving transaction with expected idx {}".format(idx))
                        transaction_exch_message: BitcopTransaction = receive(peer_socket)
                        logging.debug("Received transaction with expected idx {}".format(idx))
                        transaction_exch_code = transaction_exch_message.get_request()['code']
                        logging.debug("Code of the transaction message: {}".format(transaction_exch_code))
                        transaction = transaction_exch_message.get_request()['data']
                        logging.debug("Received transaction idx: {}".format(transaction.idx))
                        if transaction_exch_code == Bitcop.TRAN_EX and transaction.idx == idx:

                            with Lock():

                                # Updating args
                                self.pending_transactions.append(transaction)
                                self.transaction_idx += 1
                                self.ledger = transaction.ledger
                                logging.debug("Ledger and pending transactions updated with transaction {}".format(
                                    transaction.idx
                                ))

                            for peer_ip in self.neighbours_ip:

                                # Sending received transaction to neighbours
                                try:

                                    logging.debug("Sending transaction from {} to peer at {}".format(self.ip,
                                                                                                     peer_ip))
                                    self.__send_transaction(peer_ip)

                                except RuntimeError:

                                    logging.debug("Communication broken while sending transaction from {} to peer"
                                                  " at {}".format(self.ip, peer_ip))
                else:

                    logging.debug("Transaction not needed, sending TRAN_NN from {} to {}".format(self.ip,
                                                                                                 peer_address[0]))
                    transaction_no_need = BitcopTransaction(Bitcop.TRAN_NN, 'nn')
                    send(peer_socket, transaction_no_need)

            # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ BLOCK ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #

            elif peer_request_code == Bitcop.BLOCK_ID:

                # Peer block idx
                peer_block_idx = peer_request.get_request()['data']
                logging.debug("__handle_request(): Block: Block idx:{} from peer at {}:{}".format(peer_block_idx,
                                                                                                  peer_address[0],
                                                                                                  peer_address[1]))

                with Lock():

                    if self.blockchain.get_last_block() is not None:

                        latest_idx = self.blockchain.get_last_block().idx + 1

                    else:

                        latest_idx = 0

                logging.debug("__handle_request(): Block: Latest block idx: {}".format(latest_idx))

                if latest_idx <= peer_block_idx:

                    logging.debug("__handle_request(): Block: Sending latest block idx: {} to peer at {}:{}".format(
                        latest_idx,
                        peer_address[0],
                        peer_address[1]
                    ))
                    block_idx_message = BitcopBlock(Bitcop.BLOCK_ID, latest_idx)
                    send(peer_socket, block_idx_message)
                    logging.debug("__handle_request(): Block: Block idx sent")

                    for idx in range(latest_idx, peer_block_idx + 1):

                        logging.debug("__handle_request(): Block: Receiving block with idx: {} "
                                      "from peer at {}:{}".format(idx,
                                                                  peer_address[0],
                                                                  peer_address[1]))

                        block_exch_message: BitcopBlock = receive(peer_socket)
                        logging.debug("__handle_request(): Block: Block with idx: {} received".format(idx))
                        block_exch_code = block_exch_message.get_request()['code']
                        logging.debug("__handle_request(): Block: Block with idx: {} message code: {}".format(
                            idx,
                            block_exch_code
                        ))
                        block = block_exch_message.get_request()['data']

                        if block_exch_code == Bitcop.BLOCK_EX and block.idx == idx:

                            with Lock():

                                self.blockchain.add(block)
                                logging.debug("__handle_request(): Block: Block with idx: {} added to "
                                              "Blockchain".format(idx))
                                self.transaction_idx = block.transactions[-1].idx + 1
                                self.pending_transactions.clear()
                                self.ledger = block.transactions[-1].ledger
                                logging.debug("__handle_request(): Block: Transaction idx, pending transactions and "
                                              "ledger updated")

                            # Broadcast to other peers
                            for peer_ip in self.neighbours_ip:

                                logging.debug("__handle_request(): Block: Forwarding block with idx: {} to neighbour"
                                              "at {}".format(idx,
                                                             peer_ip))
                                try:

                                    logging.debug("__handle_request(): Block: Sending block with idx: {} to neighbour"
                                                  "at {}".format(idx,
                                                                 peer_ip))
                                    self.__send_block(peer_ip)
                                    logging.debug("__handle_request(): Block: Block with idx: {} sent".format(idx))

                                except RuntimeError:

                                    logging.debug("__handle_request(): Block: Communication broken while sending block"
                                                  "with idx: {} to neighbour at {}".format(idx,
                                                                                           peer_ip))
                else:

                    logging.debug("__handle_request(): Block: Block with idx: {} not needed".format(peer_block_idx))
                    logging.debug("__handle_request(): Block: Sending to block not needed to peer at {}:{}".format(
                        peer_address[0],
                        peer_address[1]
                    ))
                    block_no_need = BitcopBlock(Bitcop.BLOCK_NN, 'nn')
                    send(peer_socket, block_no_need)
                    logging.debug("__handle_request(): Block: Block not-needed sent to peer at {}:{}".format(
                        peer_address[0],
                        peer_address[1]
                    ))

        except RuntimeError:

            logging.debug("__handle_request(): Socket communication between listener {}:{}"
                          " and peer {}:{} broken".format(self.ip,
                                                          self.server_port,
                                                          peer_address[0],
                                                          peer_address[1]))

    def __authenticate(self,
                       snd_socket: socket
                       ) -> None:
        """
        Authenticates the node to the authentication center. Once the node is authenticated, its authenticated attribute
        is switched to True. The authentication sequence is based on the challenge-response scheme:
            1) node sends its user_name to the auth_center to indicate that it wants to be authenticated
            2) auth_center replies with a Nonce
            3) node replies with (user_name, sha256(nonce|secret)) with secret the shared secret
            4) auth_center replies with the list of nodes IP
        If at any point something goes wrong, each host can send an ABORT message.
        :param snd_socket: the socket used to communicate with the authentication center
        """

        try:

            # Request
            request = BitcopAuthenticate(Bitcop.AUTH_REQ,
                                         self.username)
            send(snd_socket, request)

            # Challenge
            auth_challenge = receive(snd_socket)
            chal_code = auth_challenge.get_request()['code']

            if chal_code == Bitcop.AUTH_CHAL:

                nonce = auth_challenge.get_request()['data']

                # Response
                hash_arg = nonce.to_bytes(Bitcop.NUMBER_BYTES_NONCE, byteorder) + self.secret.encode('utf-8')
                resp_data = [self.username, sha256(hash_arg).hexdigest()]

                response = BitcopAuthenticate(Bitcop.AUTH_RESP,
                                              resp_data)
                send(snd_socket, response)

                # OK
                auth_ok = receive(snd_socket)
                ok_code = auth_ok.get_request()['code']

                if ok_code == Bitcop.AUTH_OK:

                    # Node successfully authenticated
                    self.authenticated = True  # Stopping the authentication loop
                    self.peers = auth_ok.get_request()['data']
                    self.ledger = {ip: 10 for ip in self.peers}  # Initializing balance of each user to 10 BTM
                    self.peers.remove(self.ip)  # Removing own ip address from list of other users ip
                    logging.debug("Node {} successfully authenticated on the Bitcom network".format(self.username))

        except RuntimeError:
            logging.error("Socket communication broken at node {}:{}".format(self.ip,
                                                                             self.authenticate_ip))

    def __listen_forever(self) -> None:
        """
        Method running in the listening process
        """

        with socket() as node_listener:

            # Creating a socket with default mode: IPv4/TCP
            is_bound = False
            while not is_bound:

                try:
                    node_listener.bind((self.ip, self.server_port))
                    is_bound = True
                    logging.debug("Node listener bound to {}:{}".format(self.ip, self.server_port))

                except OSError:
                    logging.debug("Address {}:{} already used".format(self.ip, self.server_port))
                    sleep(1)  # Waiting one second before attempting to bind again

            node_listener.listen(5)  # Queue up to 5 connection requests
            logging.debug("Node at {}:{} is listening".format(self.ip, self.server_port))

            with Lock():
                listening_condition: bool = self.is_listening

            while listening_condition:

                peer_socket, peer_address = node_listener.accept()
                logging.debug("Peer at {}:{} is contacting listener".format(peer_address[0],
                                                                            peer_address[1]))

                if peer_address[0] in self.peers:

                    # Starting a thread to handle the request
                    request_handling_thread = Thread(target=self.__handle_request,
                                                     args=[peer_socket,
                                                           peer_address])
                    request_handling_thread.start()

                # End of loop
                with Lock():
                    listening_condition = self.is_listening

    def __mine(self) -> None:
        """
        Method used to mine blocks and to send them to neighbours
        """

        with Lock():

            mining_condition: bool = self.is_mining

        while mining_condition:

            with Lock():

                transactions_to_mine = deepcopy(self.pending_transactions)
                ledger = self.ledger
                idx = self.transaction_idx

            # First, adding Transaction.BLOCK_MINED BTM to poorest nodes

            poorest_users: List = min_args(ledger)  # IPs of the poorest users
            logging.debug("__mine(): Poorest users are {}".format(poorest_users))
            for user in poorest_users:

                transaction = Transaction(idx=idx,
                                          payee=user,
                                          amount=Transaction.BLOCK_MINED / len(poorest_users),
                                          prev_ledger=ledger)
                logging.debug("__mine(): Transaction for user {}: idx: {}, payee: {}, amount: {}".format(
                    user,
                    transaction.idx,
                    transaction.payee,
                    transaction.amount
                ))
                ledger = transaction.ledger
                idx += 1
                transactions_to_mine.append(transaction)
                logging.debug("__mine(): Transactions to be mined appended")

            # Paying miner with transaction fees

            fees = 0  # Total transaction fees accumulated

            for transaction in transactions_to_mine:

                fees += transaction.get_fees()

            logging.debug("__mine(): Total mining fees: {} BTM".format(fees))
            miner_transaction = Transaction(idx=idx,
                                            payee=self.ip,
                                            amount=fees,
                                            prev_ledger=transactions_to_mine[-1].ledger)
            logging.debug("__mine(): Transaction for miner {}: idx: {}, payee: {}, amount: {}".format(
                self.ip,
                miner_transaction.idx,
                miner_transaction.payee,
                miner_transaction.amount
            ))
            ledger = miner_transaction.ledger
            idx += 1
            transactions_to_mine.append(miner_transaction)
            logging.debug("__mine(): Transactions to be mined appended")

            try:

                with Lock():

                    if self.blockchain.get_last_block() is not None:

                        block_idx = self.blockchain.get_last_block().idx + 1
                        prev_hash = self.blockchain.get_last_block().hash

                    else:

                        # Initial conditions for the blocks

                        block_idx = 0
                        prev_hash = ""

                # Creating a block with the transactions
                block_mined = Block(idx=block_idx,
                                    prev_hash=prev_hash,
                                    transactions=transactions_to_mine)
                logging.debug("__mine(): New block with idx: {}".format(block_mined.idx))

                # Add to own Block List
                self.blockchain.add(block_mined)
                logging.debug("__mine(): Block {} added to blockchain".format(block_mined.idx))

                # Broadcast block
                logging.debug("__mine(): Submitting block {}".format(block_mined.idx))
                self.__submit_block()
                logging.debug("__mine(): Block submitted {}".format(block_mined.idx))

                with Lock():

                    self.ledger = ledger
                    self.transaction_idx = idx
                    self.pending_transactions.clear()
                    logging.debug("__mine(): Ledger, transaction idx and pending transactions updated")
                    logging.debug("__mine(): Transaction idx: {}".format(self.transaction_idx))

            except BlockNotValidException as e:

                # Hash of the block not valid for mining
                logging.debug(e.message)

            # End of mining loop
            with Lock():
                mining_condition = self.is_mining

    def __send_block(self,
                     peer_ip: str
                     ) -> None:
        """
        Sends the block to the neighbour at neighbour_ip
        :param peer_ip: ip where block must be sent
        """

        try:

            with socket() as snd_socket:

                logging.debug("__send_block(): Peer receiving transaction: {}".format(peer_ip,
                                                                                      self.server_port))
                try:

                    snd_socket.bind((self.ip, 0))
                    snd_socket.connect((peer_ip, self.server_port))
                    logging.debug("__send_block(): Connected to peer at {}:{}".format(peer_ip,
                                                                                      self.server_port))

                except OSError:

                    logging.debug("__send_block(): Could not connect to peer at {}:{}".format(peer_ip,
                                                                                              self.server_port))
                    return

                with Lock():

                    last_idx = self.blockchain.get_last_block().idx
                    logging.debug("__send_block(): Latest block idx: {} from peer at {}".format(last_idx,
                                                                                                peer_ip))

                # Send last block idx to peer
                block_idx = BitcopBlock(Bitcop.BLOCK_ID, last_idx)
                logging.debug("__send_block(): Sending block idx to peer at {}".format(peer_ip))
                send(snd_socket, block_idx)
                logging.debug("__send_block(): Block idx sent to peer at {}".format(peer_ip))

                # Receive last block idx from peer
                logging.debug("__send_block(): Receiving last block idx from peer at {}".format(peer_ip))
                block_idx_peer = receive(snd_socket)
                logging.debug("__send_block(): Received last block idx from peer at {}".format(peer_ip))
                block_idx_peer_code = block_idx_peer.get_request()['code']
                logging.debug("__send_block(): Peer block idx message code: {} from peer at {}".format(
                    block_idx_peer_code,
                    peer_ip
                ))

                if block_idx_peer_code == Bitcop.BLOCK_ID:

                    # Send required blocks to peer
                    last_idx_peer = block_idx_peer.get_request()['data']
                    logging.debug("__send_block(): Latest block idx: {} from peer at {}".format(last_idx_peer,
                                                                                                peer_ip))

                    with Lock():

                        last_idx = self.blockchain.get_last_block().idx
                        logging.debug("__send_block(): idx of the last block: {} from peer at {}".format(last_idx,
                                                                                                         peer_ip))

                    for idx in range(last_idx_peer, last_idx + 1):

                        with Lock():

                            snd_block = self.blockchain.chain[idx]

                        block_message = BitcopBlock(Bitcop.BLOCK_EX, snd_block)
                        logging.debug("__send_block(): Sending block with idx: {} to peer at {}".format(idx,
                                                                                                        peer_ip))
                        send(snd_socket, block_message)
                        logging.debug("__send_block(): Block with idx: {} sent to peer at {}".format(idx,
                                                                                                     peer_ip))

                elif block_idx_peer_code == Bitcop.BLOCK_NN:

                    logging.debug("__send_block(): Peer at {} does not need the block".format(peer_ip))

        except RuntimeError:

            logging.debug("__send_block(): Socket communication broken while sending blocks to peer at {}:{}".format(
                peer_ip,
                self.server_port
            ))

    def __submit_block(self) -> None:
        """
        Submits a new block to the network.
        """

        if self.authenticated:

            for peer_ip in self.neighbours_ip:

                with Lock():

                    idx = self.blockchain.get_last_block().idx

                logging.debug("Try to send the block with index {} to its neighbours".format(idx))
                self.__send_block(peer_ip)

        else:

            print("Not authenticated on the BITCOM network, cannot submit blocks.")
            print("Please restart the program...")

    def __send_transaction(self,
                           peer_ip: str
                           ) -> None:
        """
        Sends the transaction to the neighbour at neighbour_ip
        :param peer_ip: ip where transaction must be sent
        """

        try:

            with socket() as snd_socket:

                # Creating a socket with default mode: IPv4/TCP
                logging.debug("Peer receiving transaction: {}".format(peer_ip,
                                                                      self.server_port))

                try:

                    snd_socket.bind((self.ip, 0))  # OS takes care of free port allocation
                    snd_socket.connect((peer_ip, self.server_port))

                except OSError:
                    logging.debug("Could not connect to peer at {}:{}".format(peer_ip,
                                                                              self.server_port))
                    return

                # Send transaction idx
                with Lock():

                    last_idx = self.pending_transactions[-1].idx

                tran_idx = BitcopTransaction(Bitcop.TRAN_ID,
                                             last_idx)
                logging.debug("Latest transaction idx: {}".format(last_idx))

                logging.debug("Sending transaction idx to peer at {}".format(peer_ip))
                send(snd_socket, tran_idx)
                logging.debug("Transaction idx sent to peer at {}".format(peer_ip))

                # Receive last transaction idx of the peer
                logging.debug("Receiving last transaction idx from peer at {}".format(peer_ip))
                tran_idx_peer = receive(snd_socket)
                logging.debug("Received last transaction from peer at {}".format(peer_ip))
                tran_idx_peer_code = tran_idx_peer.get_request()['code']
                logging.debug("Latest transaction idx message code: {}".format(tran_idx_peer_code))

                if tran_idx_peer_code == Bitcop.TRAN_ID:

                    last_idx_peer = tran_idx_peer.get_request()['data']
                    logging.debug("Latest transaction idx of peer: {}".format(last_idx_peer))

                    with Lock():

                        first_idx_pending = self.pending_transactions[0].idx
                        logging.debug("idx of the first pending transaction: {}".format(first_idx_pending))

                    # Send required transactions
                    # Assuming that only the pending transactions need to be synced
                    for idx in range(last_idx_peer, last_idx + 1):

                        with Lock():

                            snd_transaction = self.pending_transactions[idx - first_idx_pending]

                        transaction_message = BitcopTransaction(Bitcop.TRAN_EX,
                                                                snd_transaction)
                        logging.debug("Sending transaction with idx: {} to peer".format(idx - first_idx_pending))
                        send(snd_socket, transaction_message)
                        logging.debug("Transaction with idx: {} sent to peer".format(idx - first_idx_pending))

                elif tran_idx_peer_code == Bitcop.TRAN_NN:

                    # Peer does not need the transactions
                    logging.debug("Peer does not need the transactions")

        except RuntimeError:

                logging.debug("Socket communication broken while sending transactions to peer at {}:{}".format(
                    peer_ip,
                    self.server_port
                ))

    def submit_transaction(self,
                           payee: str,
                           amount: float
                           ) -> None:
        """
        Submits a transaction to the network. Adds it to the pending transactions list.
        :param payee: ip of the user receiving the money
        :param amount: amount of money transferred
        """

        if self.authenticated:

            # Required to be authenticated to submit a transaction
            if payee in self.peers:

                # Payee is valid
                with Lock():

                    transaction_idx = self.transaction_idx
                    payer = self.ip
                    ledger = self.ledger

                transaction: Transaction = Transaction(transaction_idx,
                                                       payer,
                                                       payee,
                                                       amount,
                                                       ledger)  # Exception raised if amount > balance
                with Lock():

                    # Updating args
                    self.ledger = transaction.ledger
                    self.pending_transactions.append(transaction)
                    self.transaction_idx += 1
                    logging.debug("Ledger and pending transactions updated")

                # Sending transaction to neighbours
                for peer_ip in self.neighbours_ip:

                    try:

                        logging.debug("Sending transaction to peer {}".format(peer_ip))
                        self.__send_transaction(peer_ip)

                    except RuntimeError:

                        logging.warning("Transaction with index {} could not be sent to {}".format(transaction.idx,
                                                                                                   peer_ip))

            else:

                # Invalid payee
                raise TransactionNotValidException(nodes=self.peers)

        else:

            message: str = 'Not authenticated on the network. Cannot submit transaction.'
            raise TransactionNotValidException(message=message)

    # ----------------------------------------------------- RUN ----------------------------------------------------- #

    def run(self) -> None:
        """
        Main method of the Node thread :
            1. tries to be authenticated on the network by the authentication center
            2. starts the server
            3. starts the mining
        """

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ AUTHENTICATION ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #

        with socket() as auth_client:

            # Creating a socket with default mode: IPv4/TCP
            auth_server_address = (self.authenticate_ip,
                                   self.server_port)

            try:
                auth_client.bind((self.ip, 0))  # OS takes care of free port allocation
                auth_client.connect(auth_server_address)

            except OSError:
                logging.debug("Server at {}:{} cannot be reached".format(self.authenticate_ip,
                                                                         self.server_port))
                return

            while not self.authenticated:
                # Trying to be authenticated on the network
                self.__authenticate(auth_client)

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ SERVER ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #

        # Creating and starting the server thread
        listening_thread = Thread(target=self.__listen_forever)
        with Lock():
            self.is_listening = True

        listening_thread.start()

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ MINING ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #

        # Creating and starting the thread
        mining_thread = Thread(target=self.__mine)
        with Lock():
            self.is_mining = True

        mining_thread.start()
