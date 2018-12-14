# !/usr/bin/env python3
# -*- coding: utf-8 -*-

__date__ = "27.11.2018"

"""
This module contains the helping functions used to format data structures
"""

# ----------------------------------------------------- IMPORTS ----------------------------------------------------- #

# For types

from typing import Dict

# For formatting

from sys import byteorder
from configparser import ConfigParser

# For file explorer

from pathlib import Path

# ---------------------------------------------------- FUNCTIONS ---------------------------------------------------- #

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ PARSING CONFIG FILES ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #


def parse_config_node(index: int) -> Dict:
    """
    Parses the .ini conf file related to the node at index. The conf file has the structure:
        {node: {ip_address, user_name}, registration: {authenticate_ip, secret}, neighbours: [neighbour_ip]}
    :param index: index of the node
    :return: a dictionary with the data stored in the conf file
    """

    # Finding the path to config file

    file_name = "host_{}.ini".format(index)
    pwd = Path.cwd()
    if 'blockchain' == str(pwd).split('/')[-1]:

        # pwd is blockchain
        blockchain_path = pwd

    else:

        # pwd is blockchain/src
        blockchain_path = pwd.parent

    conf_path = blockchain_path / "config" / file_name

    # Opening and reading the file

    parser = ConfigParser(allow_no_value=True)
    parser.read(conf_path)

    # Formatting the result in the correct way

    return {'node': dict(parser.items('node')),
            'registration': dict(parser.items('registration')),
            'neighbours': [elem[0] for elem in parser.items('neighbours')]}


def parse_config_auth_center() -> Dict:
    """
    Parses the .ini conf file related to the authentication center. The conf file has the structure:
        {authenticate: ip_address, nodes: {ip_address, secret}}
    :return: a dictionary with the data stored in the conf file
    """

    # Finding the path of config file

    file_name = "authenticate.ini"
    pwd = Path.cwd()
    if 'blockchain' == str(pwd).split('/')[-1]:

        # pwd is blockchain
        blockchain_path = pwd

    else:

        # pwd is blockchain/src
        blockchain_path = pwd.parent

    conf_path = blockchain_path / "config" / file_name

    # Opening and reading the file

    parser = ConfigParser()
    parser.read(conf_path)

    # Formatting the result in the correct way

    return {'ip_address': parser['authenticate']['ip_address'],
            'nodes': dict(parser.items('nodes'))}

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ FORMATTING BYTES ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #


def parse_bytes_stream_from_message(msg: bytes,
                                    length_bytes: int,
                                    code_bytes: int
                                    ) -> Dict:

    """
    Decapsulates the information contained in the message bytes as a dictionary
    :param msg: Bytes given in the format defined in the Bitcop protocol :
        Length | Code | Data
    :param length_bytes: number of bytes used to represent the length of the message
    :param code_bytes: number of bytes used to represent the message codes
    :return: A dictionary : {"Code": Code,
                            "Data": Data}
    """

    code = int.from_bytes(msg[length_bytes:
                              length_bytes + code_bytes],
                          byteorder)
    data = msg[length_bytes + code_bytes:]

    return {"code": code,
            "data": data}



