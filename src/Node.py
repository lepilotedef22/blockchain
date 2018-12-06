from src import TX
from threading import Thread
import time

class Node(Thread):
    def __init__(self, ip):
        super().__init__()
        self.nodeTX = TX(ip, 4243)
        #TODO
        print("New node")

    def run(self) -> None:
        self.nodeTX.send("127.0.0.1", 4242, "Hello world")
        time.sleep(1)
        self.nodeTX.send("127.0.0.1", 4242, "I'm Alice")
        time.sleep(1)
        self.nodeTX.send("127.0.0.1", 4242, "You are Bob")
