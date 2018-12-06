from src.model.RX import RX
from src.model.TX import TX
import threading
from src import Authenticate
from src import Node


class Launcher:

    def __init__(self):
        # Not working
        print("New simulation started")
        self.auth = Authenticate()
        self.node = Node("127.0.0.2")


if __name__ == "__main__":
    launcher = Launcher()
    launcher.auth.start()
    launcher.node.start()
