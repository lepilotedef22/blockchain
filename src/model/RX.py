
from socket import *


class RX:

    # Initializer / Instance Attributes
    def __init__(self, IP, port):
        self.IP = IP
        self.port = port

    def receive(self):
        rx_socket = socket(AF_INET, SOCK_STREAM)
        rx_socket.bind(self.IP, self.port)
        rx_socket.listen(1)

        while True:
            tx_socket, tx_address = rx_socket.accept()
            message = tx_socket.recv(1024).decode()
            tx_socket.close()
            return message

