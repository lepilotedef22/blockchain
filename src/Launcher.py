from src.model.RX import RX
from src.model.TX import TX


class Launcher:

    def __init__(self):
        # Not working
        print("New simulation started")
        rx = RX("localhost", 27015)
        tx = TX("localhost", 4242)
        tx.send("localhost", 27015, "J'essaie")
        message = rx.receive()
        print(message)


if __name__ == "__main__":
    Launcher()
