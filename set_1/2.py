#!/usr/bin/env python

import cryptolib

s1 = "1c0111001f010100061a024b53535009181c"
s2 = "686974207468652062756c6c277320657965"

if __name__ == "__main__":
    print cryptolib.hex_strings_xor(s1, s2)
    
