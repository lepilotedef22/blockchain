

class CommunicationHandler:

    def __init__(self, client, rx):
        self.client = client
        self.rx = rx


    def transmitMessage(self, destination, message):
        destination.receive(message)
