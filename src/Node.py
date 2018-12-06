from src import TX
from threading import Thread
import time
from src.model import Constants
from hashlib import sha256


class Node(Thread):
    def __init__(self, ip):
        super().__init__()
        self.authTX = TX(ip, 4243, Constants.server_ip, 4242)
        #TODO
        print("New node")

    def authenticate(self):
        self.authTX.send(Constants.AUTH_MSG)

    def run(self) -> None:
        nonce = "abc"
        password = "12345"
        self.authenticate()
        self.authTX.send("username:Martine")
        time.sleep(1)
        self.authTX.send("password:" + sha256((nonce + password).encode('utf-8')).hexdigest())
        time.sleep(1)
        self.authTX.send("I'm Alice")
        time.sleep(1)
        self.authTX.send("You are Bob")
