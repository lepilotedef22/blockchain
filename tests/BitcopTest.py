# !/usr/bin/env python3
# -*- coding: utf-8 -*-

__date__ = "12.12.2018"

# ----------------------------------------------------- IMPORTS ----------------------------------------------------- #

from unittest import TestCase, main
from src import Bitcop, BitcopAuthenticate, CodeNotValidException

# ------------------------------------------------------ TESTS ------------------------------------------------------ #


class BitcopTest(TestCase):
    """
    This test file assesses the Bitcop classes for the Bitcop protocol
    """

    def test_code_not_valid_exception(self):
        """
        Tests if the CodeNotValidException is raised
        """

        with self.assertRaises(CodeNotValidException):

            BitcopAuthenticate(Bitcop.DEFAULT)

#  -----------------------------------------------------LAUNCHER ----------------------------------------------------- #


if __name__ == '__main__':
    main()
