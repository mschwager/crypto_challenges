#!/usr/bin/env python

import base64
import cryptolib

KEY = "YELLOW SUBMARINE"
IV = ''.join(["\x00"] * len(KEY))

lines = [l.strip() for l in open("10.txt").readlines()]
buf = base64.b64decode("".join(lines))

if __name__ == "__main__":
    print cryptolib.aes_cbc_decrypt(KEY, buf, IV)
