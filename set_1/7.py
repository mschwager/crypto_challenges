#!/usr/bin/env python

import base64
import cryptolib

lines = [l.strip() for l in open("7.txt").readlines()]
ss = base64.b64decode("".join(lines))

KEY = b"YELLOW SUBMARINE"

if __name__ == "__main__":
    print cryptolib.aes_decrypt(KEY, ss)
