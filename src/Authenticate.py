# !/usr/bin/env python3
# -*- coding: utf-8 -*-

# ----------------------------------------------------- IMPORTS ----------------------------------------------------- #

from typing import Dict, Tuple
from threading import Thread
from src import parse_config_auth_center, receive, send, Bitcop, BitcopAuthenticate
from socket import socket
from random import getrandbits
from hashlib import sha256
from sys import byteorder
from time import sleep


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

        # Parsing config file
        config = parse_config_auth_center()
        self.ip: str = config['ip_address']
        self.port: int = 5001
        self.all_nodes: Dict[str, str] = config['nodes']  # {ip, secret}
        #  self.nodes_to_connect: Dict[str, str] = config['nodes']  # TODO: check whether it is useful

    # --------------------------------------------------- METHODS --------------------------------------------------- #

    def __authenticate(self,
                       client_sock: socket,
                       client_address: Tuple[str, int]
                       ) -> None:
        """
        Authenticates the node to the authentication center. The authentication sequence is based on the
        challenge-response scheme:
            1) node sends its user_name to the auth_center to indicate that it wants to be authenticated
            2) auth_center replies with a Nonce
            3) node replies with [user_name, sha256(nonce|secret)] with secret the shared secret
            4) auth_center replies with ok
        If at any point something goes wrong, each host can send an ABORT message.
        :param client_sock: socket of the node requesting authentication
        :param client_address: client address: (ip, port)
        """

        try:

            # Request

            auth_req = receive(client_sock)
            req_code = auth_req.get_request()['code']
            user_name = auth_req.get_request()['data']
            node_ip = client_address[0]

            if req_code == Bitcop.AUTH_ABORT:

                # Client aborted the operation
                return

            elif req_code != Bitcop.AUTH_REQ:

                # Code does not match that of a request
                abort_req = BitcopAuthenticate(Bitcop.AUTH_ABORT,
                                               'abort')
                send(client_sock, abort_req)
                return

            # Challenge

            nonce: int = getrandbits(8 * Bitcop.NUMBER_BYTES_NONCE)
            chal_req = BitcopAuthenticate(Bitcop.AUTH_CHAL, nonce)
            send(client_sock, chal_req)

            # Response

            secret = self.all_nodes[node_ip]
            hash_arg = nonce.to_bytes(Bitcop.NUMBER_BYTES_NONCE, byteorder) + secret.encode('utf-8')
            expected_hash = sha256(hash_arg).hexdigest()
            expected_response = [user_name, expected_hash]

            auth_resp = receive(client_sock)
            resp_code = auth_resp.get_request()['code']
            response = auth_resp.get_request()['data']

            if resp_code == Bitcop.AUTH_ABORT:

                # Client aborted the operation
                return

            elif resp_code == Bitcop.AUTH_RESP:

                # Code matches that of a response
                if response == expected_response:

                    # Correct response, node can be authenticated
                    auth_ok = BitcopAuthenticate(Bitcop.AUTH_OK)
                    send(client_sock, auth_ok)
                    print("Server successfully authenticated node at {}".format(client_address[0]))
                    return

                else:

                    # Wrong response, aborting operation
                    abort_req = BitcopAuthenticate(Bitcop.AUTH_ABORT,
                                                   'abort')
                    send(client_sock, abort_req)
                    return

            else:

                # Code does not match that of a response
                abort_req = BitcopAuthenticate(Bitcop.AUTH_ABORT,
                                               'abort')
                send(client_sock, abort_req)
                return

        except RuntimeError:
            print("Socket communication broken with node at {0}:{1}".format(client_address[0],
                                                                            client_address[0]))

    # ----------------------------------------------------- RUN ----------------------------------------------------- #

    def run(self) -> None:
        """
        Main process of the Authentication thread. Its aim is to start the authenticate server, and then to intercept
        client requests that will be handled in other threads.
        """

        with socket() as auth_server:

            # Setting up connection
            auth_server_address = (self.ip, self.port)
            is_bound = False

            while not is_bound:

                try:
                    auth_server.bind(auth_server_address)
                    is_bound = True

                except OSError:
                    print("Address {0}:{1} already used".format(self.ip, self.port))
                    sleep(1)  # Waiting one second before attempting to bind again

            auth_server.listen(5)  # Queue up to 5 client sockets
            print("Authentication server listening at {0}:{1}\n".format(self.ip,
                                                                        self.port))

            # ---------------------------------------------- MAIN LOOP ---------------------------------------------- #

            while True:

                # Intercepting new client requests
                node_sock, node_address = auth_server.accept()

                print("Node at {0}:{1} is contacting the authentication server".format(node_address[0],
                                                                                       node_address[1]))

                if node_address[0] in self.all_nodes:

                    # Node sending the request is eligible for an authentication

                    # Creating the thread handling the client socket
                    client_thread = Thread(target=self.__authenticate, args=[node_sock,
                                                                             node_address])

                    # Starting the thread
                    client_thread.start()

                else:

                    # Node is unknown on the network, aborting operation
                    abort_req = BitcopAuthenticate(Bitcop.AUTH_ABORT,
                                                   'abort')
                    send(node_sock, abort_req)

                sleep(0.01)

# ------------------------------------------------------- MAIN ------------------------------------------------------- #


if __name__ == "__main__":

    auth = Authenticate()
    auth.start()
