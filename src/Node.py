from src import TX
from threading import Thread

class Node(Thread):
    def __init__(self):
        super().__init__()
        self.nodeTX = TX("localhost", 4243)
        #TODO
        print("New node")

    def run(self) -> None:
        self.nodeTX.send("localhost", 4242, "Hello world")
