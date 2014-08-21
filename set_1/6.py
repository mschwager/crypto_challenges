#!/usr/bin/env python

import base64
import cryptolib

lines = [l.strip() for l in open("6.txt").readlines()]
s = base64.b64decode("".join(lines))

if __name__ == "__main__":
    print s

