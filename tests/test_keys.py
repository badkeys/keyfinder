import binascii
import unittest
import os
import re

import keyfinder

TDPATH = f"{os.path.dirname(__file__)}/data/"


class TestKeys(unittest.TestCase):

    def test_valid(self):
        # For each key in testdata/valid, we expect a string
        # of the form spkisha256:[hash] in the same file.
        for fn in os.listdir(f"{TDPATH}/valid/"):
            with open(f"{TDPATH}/valid/{fn}", "rb") as f:
                data = f.read()
            expect = set()
            for r in re.findall(b"spkisha256:[0-9a-f]*", data):
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
            with open(f"{TDPATH}/invalid/{fn}", "rb") as f:
                data = f.read()
            keys = keyfinder.findkeys(data, usebk=False)
            self.assertEqual(keys, {})
