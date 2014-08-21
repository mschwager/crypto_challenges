#!/usr/bin/env python

import cryptolib

s = """Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal"""
key = "ICE"

if __name__ == "__main__":
    print cryptolib.repeated_xor_encrypt(s, key)

