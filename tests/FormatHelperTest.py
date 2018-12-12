# !/usr/bin/env python3
# -*- coding: utf-8 -*-

__date__ = "29/11/2018"

# ----------------------------------------------------- IMPORTS ----------------------------------------------------- #

from unittest import TestCase, main
from src import parse_config_node, parse_config_auth_center

# ------------------------------------------------------ TESTS ------------------------------------------------------ #


class FormatHelperTest(TestCase):

    """
    This test file assesses the ComHelperModule
    """

    def test_node_config_parser(self):
        """
        Tests the parse_config_node function
        """

        expected_dico = {
            'node': {'ip_address': '127.0.1.1', 'username': 'host_1'},
            'registration': {'ip_address': '127.0.0.10', 'secret': 'host_1_secret'},
            'neighbours': ['127.0.2.1', '127.0.3.1']
        }

        self.assertEqual(parse_config_node(1), expected_dico)

    def test_auth_center_config_parser(self):
        """
        Tests the parse_config_auth_center function
        """

        expected_dico = {
            'ip_address': '127.0.0.10',
            'nodes': {
                '127.0.1.1': 'host_1_secret',
                '127.0.2.1': 'host_2_secret',
                '127.0.3.1': 'host_3_secret',
                '127.0.4.1': 'host_4_secret',
                '127.0.5.1': 'host_5_secret',
                '127.0.6.1': 'host_6_secret'
            }
        }

        self.assertEqual(parse_config_auth_center(), expected_dico)

#  -----------------------------------------------------LAUNCHER ----------------------------------------------------- #


if __name__ == '__main__':
    main()
