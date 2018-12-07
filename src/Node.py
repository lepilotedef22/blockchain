from src import TX
from src import RX
from threading import Thread
import time
from src.model import Constants
from hashlib import sha256
from sys import byteorder
from socket import socket


class Node(Thread):
    def __init__(self, ip):
        super().__init__()
        self.ip = ip
        self.username = "Alice"
        self.password = "1234"
        self.authTX = TX(ip, 4243, Constants.server_ip, 4242)
        self.socket = socket()  # AF_INET and SOCK_STREAM are default values
        self.socket.bind((self.ip, 4242))
        self.socket.listen(5)
        #TODO
        print("New node")

    @staticmethod
    def receive(client_socket, protocol=None, **kwargs) -> str:
        if protocol is not None:

                # bi-directional communication

            protocol(kwargs)

        else:

                # uni-directional communication

            chunks = []
            bytes_received = 0
            number_length_coding_bytes = 2
            length_coding_bytes = int.from_bytes(client_socket.recv(number_length_coding_bytes), byteorder)
            max_length = length_coding_bytes
            bytes_received += number_length_coding_bytes

            while bytes_received < max_length:

                chunk = client_socket.recv(min(max_length - bytes_received, 1024))  # 4096 is arbitrary

                if chunk == b"":
                    raise RuntimeError("Socket connection broken")

                chunks.append(chunk)
                bytes_received += len(chunk)

            return b"".join(chunks).decode("utf-8")

    def authenticate(self):
        c, addr = self.socket.accept()
        self.authTX.send(Constants.AUTH_MSG)
        nonce = self.receive(c)
        time.sleep(0.1)
        self.authTX.send(Constants.AUTH_USR + self.username)
        time.sleep(0.1)
        hash = sha256((nonce + self.password).encode('utf-8')).hexdigest()
        self.authTX.send(Constants.AUTH_PSWD + hash)
        response = self.receive(c)
        print(response)

    def run(self) -> None:
        self.authenticate()
