import src.model.RX as RX
import src.model.TX as TX

class Launcher:

    def __init__(self):
        # Not working
        print("New simulation started")
        rx = RX("localhost",27015)
        tx = TX()
        tx.send("localhost",27015, "J'essaie")
        message = rx.receive()
        print(message)
