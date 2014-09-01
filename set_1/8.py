#!/usr/bin/env python

import cryptolib

lines = [l.strip() for l in open("8.txt").readlines()]

KEY_SIZES = [16, 24, 32]

if __name__ == "__main__":
    split_hex = [cryptolib.hex_string_split(l) for l in lines]

    hammings = []
    for key_size in KEY_SIZES:
        for line_no, line in enumerate(split_hex):
            chrs = [chr(int(c, 16)) for c in line]
            hex_string = ''.join(chrs)

            hamming = cryptolib.chunk_hamming_distance(hex_string, key_size)
            hammings.append((line_no, key_size, hamming))

    result = sorted(hammings, key=lambda x: x[2])[0]

    print "LINE: {}, KEY SIZE: {}".format(result[0], result[1])
