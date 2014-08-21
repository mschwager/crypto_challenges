#!/usr/bin/env python

import string

import cryptolib

s = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"

if __name__ == "__main__":
    characters = string.ascii_uppercase + string.ascii_lowercase

    analysis = {}
    for c in characters:
        decrypted = cryptolib.xor_decrypt_hex_string_with_chr(s, c)

        # Frequency table is in upper case
        decrypted_upper = [d.upper() for d in decrypted]

        decrypted_frequency = cryptolib.frequency_avg(decrypted_upper)
        analysis[c] = cryptolib.frequency_analysis(decrypted_frequency,
            truth=cryptolib.ENGLISH_FREQUENCIES_WITH_SPACE)

    sorted_analysis = sorted(analysis.items(), key=lambda a: a[1])

    print "decrypting with best option found..."
    print cryptolib.xor_decrypt_hex_string_with_chr(s, sorted_analysis[0][0])
