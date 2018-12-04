# !/usr/bin/env python3
# -*- coding: utf-8 -*-

__date__ = "29/11/2018"

# ----------------------------------------------------- IMPORTS ----------------------------------------------------- #

from unittest import TestCase, main
from src import parse_config

# ------------------------------------------------------ TESTS ------------------------------------------------------ #


class ComHelperTest(TestCase):

    """
    This test file assesses the ComHelperModule
    """

    def test_config_parser(self):

        """
        Tests the config_parser function
        """

        expected_dico = {
            'node': {'ip_address': '127.0.0.1', 'username': 'host_1'},
            'registration': {'ip_address': '127.0.0.10', 'secret': 'host_1_secret'},
            'neighbours': ['127.0.0.2', '127.0.0.3']
        }

        self.assertEqual(parse_config(1), expected_dico)

#  -----------------------------------------------------LAUNCHER ----------------------------------------------------- #


if __name__ == '__main__':
    main()
