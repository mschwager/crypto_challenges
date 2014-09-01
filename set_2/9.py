#!/usr/bin/env python

import cryptolib

KEY = "YELLOW SUBMARINE"

if __name__ == "__main__":
    print cryptolib.pkcs_7_pad(KEY, 20)
