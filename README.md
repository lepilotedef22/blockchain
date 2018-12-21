Blockchain project
Bitcom
ELEC-H417


Teacher: Jean-Michel Dricot
Assistant: Soultana Ellinidou

Students: Wilson Daubry, Léonard Steyaert, Arthur Van Heirstraeten, Denis Verstraeten
Date: 21 December 2018



1. Introduction
~~~~~~~~~~~~~~~~
The aim of this project was to develop a basic blockchain. For more information, the reader is suggested to check the report which goes with greater length into the details. This README presents the features and then explains how to use them. We hope you will enjoy testing and using our Bitcom blockchain.

2. Features
~~~~~~~~~~~~
- The nodes of the network first need to be authenticated by the authentication center. This is done using the challenge-response scheme. The authentication center being the only one knowing all the nodes on the network, it sends this information to any node being accredited on the network, so that it can communicate with its peers.
- The node can be controlled by a command line interface. The list of the available commands can be accessed at any time by typing "help". The interface has different features:

	* status: shows the connection status of the node on the network, its IP address, its current balance and the index and the hash of the last block in the blockchain.

	* pay: allows to send money to another user, and makes sure there is no over-spending, even with the transaction fees (more about that later).

	* transactions: shows the history of all the transactions of this node in an anti-chronological order. Shows the difference between the transactions already in a block and those still pending.

	* exit: properly shuts down the node.

The basic documentation of each of this feature can be accessed by typing <feature> -h (or <feature> --help).
- To mine a block, the hash of the block needs to start with 5 zeros. The original feature of the Bitcom blockchain is that it does not gift the miner with the created money, but offers it to the poorest user(s). The miners are incentivised to mine using the transaction fees introduced previously. Each transaction from node to node is subject to a 1% fee. These fees are collected and given to the miner who mined the block. The money received from the network and not from a user is free of any fee. The name of the money is the Bitcom (BTM). The poorest user(s) share 1 BTM when a block is mined.

3. Manual
~~~~~~~~~~

- Starting the network: 
	* One needs to start by launching the Authenticate Center (Authenticate.py), otherwise at this point the nodes will not be able to authenticate.
	
	* Then, the nodes are started with NodeShell.py -<node number> [--log <log level>]. Node number goes from 1 to 6. Log is related to a logging system used to debug (cf. https://docs.python.org/3/library/logging.html).

	* Concerning the authentication process, no intervention from the user is required. The authentication state can be checked using "status".

	* To use the payment system, the command is as follows: pay [payee ip] [amount]. After you typed this, the interface will tell you how much it will amount to with the 1% transaction fee. If you agree to pay this amount, just type "y" or "yes". (The interface will guide you at each step).


Have fun using the Bitcom blockchain payment system!



	