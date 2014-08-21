#!/usr/bin/env python

import string

import cryptolib

ss = [l.strip() for l in open("4.txt").readlines()]

if __name__ == "__main__":

    # Tricky, tricky, took me awhile to figure out I should use digits also
    characters = string.ascii_uppercase + string.ascii_lowercase + string.digits

    line_analysis = {}
    for i, s in enumerate(ss):
        analysis = {}
        for c in characters:
            decrypted = cryptolib.xor_decrypt_hex_string_with_chr(s, c)

            # Frequency table is in upper case
            decrypted_upper = [d.upper() for d in decrypted]

            decrypted_frequency = cryptolib.frequency_avg(decrypted_upper)
            analysis[c] = cryptolib.frequency_analysis(decrypted_frequency,
                truth=cryptolib.ENGLISH_FREQUENCIES_WITH_SPACE)

        for k, v in analysis.items():
            line_analysis["{}-{}".format(i, k)] = v

    sorted_line_analysis = sorted(line_analysis.items(), key=lambda l: l[1])

    print "decrypting with best option found..."
    line, char = sorted_line_analysis[0][0].split('-')
    print cryptolib.xor_decrypt_hex_string_with_chr(ss[int(line)], char)

