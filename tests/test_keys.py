import binascii
import os
import pathlib
import re
import unittest

import keyfinder

TDPATH = f"{os.path.dirname(__file__)}/data/"


class TestKeys(unittest.TestCase):

    def test_valid(self):
        # For each key in testdata/valid, we expect a string
        # of the form spkisha256:[hash] in the same file.
        for fn in os.listdir(f"{TDPATH}/valid/"):
            # we need to reset those for each testcase
            keyfinder.dups = set()
            keyfinder.pdups = set()

            data = pathlib.Path(f"{TDPATH}/valid/{fn}").read_bytes()
            expect = set()
            for r in re.findall(rb"spkisha256:[0-9a-f]*", data):
                expect.add(binascii.unhexlify(r[11:]))
            keys = keyfinder.findkeys(data, usebk=False)
            self.assertTrue(keys, msg=f"Error with {fn}")
            found = set(keys.keys())
            self.assertEqual(found, expect, msg=f"Error with {fn}")

    def test_invalid(self):
        # The testdata/invalid dir contains broken keys that
        # we should not import, but they should not cause
        # crashes or unhandled exceptions.
        for fn in os.listdir(f"{TDPATH}/invalid/"):
            data = pathlib.Path(f"{TDPATH}/invalid/{fn}").read_bytes()
            keys = keyfinder.findkeys(data, usebk=False)
            self.assertEqual(keys, {})
