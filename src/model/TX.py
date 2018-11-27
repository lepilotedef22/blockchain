# !/usr/bin/env python3
# coding: utf-8

__author__ = "Denis Verstraeten & Arthur Van Heirstraeten"
__date__ = "27.11.2018"

# ------------------------------------------------------ IMPORT ------------------------------------------------------ #

import socket


class TX:

    def __init__(self, ip, port):

        self.ip = ip
        self.port = port

    def send(self, dest_ip, dest_port, msg):

        """

        :param dest_ip:
        :param dest_port:
        :param msg:
        :return:
        """

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind((self.ip, self.port))
        s.connect((dest_ip, dest_port))
        s.send(str.encode(msg))
        s.close()
