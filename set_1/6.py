#!/usr/bin/env python

import string
import base64
import cryptolib

lines = [l.strip() for l in open("6.txt").readlines()]
ss = base64.b64decode("".join(lines))

if __name__ == "__main__":

    # Generalize method suggested in problem to get hamming distance of 1-2
    # chunks of cipher text to use all chunks
    sizes = []
    for keysize in xrange(2, 41):
        hamming = cryptolib.chunk_hamming_distance(ss, keysize)

        sizes.append((keysize, float(hamming)))

    sorted_sizes = sorted(sizes, key=lambda x: x[1])
    top = [i[0] for i in sorted_sizes][0]
    print "TOP KEYSIZE: {}".format(top)

    ss = ''.join([hex(ord(i))[2:].zfill(2) for i in ss])
    ss = cryptolib.hex_string_split(ss)
    characters = string.printable

    # Makes a list of [first byte of every block, second ..., third ..., ...]
    blocks = cryptolib.divvy(ss, top)

    result = []
    for block in blocks:
        s = ''.join(block)
        analysis = {}
        for char in characters:
            decrypted = cryptolib.xor_decrypt_hex_string_with_chr(s, char)

            # Frequency table is in upper case
            decrypted_upper = [d.upper() for d in decrypted]

            decrypted_frequency = cryptolib.frequency_avg(decrypted_upper)
            analysis[char] = cryptolib.frequency_analysis(decrypted_frequency,
                truth=cryptolib.ENGLISH_FREQUENCIES_WITH_SPACE)

        sorted_analysis = sorted(analysis.items(), key=lambda a: a[1])
        result += sorted_analysis[0][0]

    print ''.join(result)

