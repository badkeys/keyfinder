#!/usr/bin/python3

import argparse
import base64
import binascii
import datetime
import hashlib
import os
import re
import sys
import urllib.parse
import warnings

import bs4
import requests
import urllib3
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization

usebk = True
try:
    import badkeys
except ImportError:
    print("WARNING: Could not load badkeys, not checking for known keys")
    usebk = False

rex_t = r"-----BEGIN[A-Z ]* PRIVATE KEY-----.*?-----END[A-Z ]* PRIVATE KEY-----"
rex = re.compile(rex_t, flags=re.MULTILINE | re.DOTALL)
# rex_b = b"-----BEGIN[A-Z ]* PRIVATE KEY-----.*?-----END[A-Z ]* PRIVATE KEY-----"
# rex = re.compile(rex_b, flags=re.MULTILINE | re.DOTALL)

dups = set()
pdups = set()


def filter_none(inkey):
    return inkey


# un-escape escaped chars like \n
def filter_unesc(inkey):
    return inkey.encode().decode("unicode_escape", errors="ignore")


def filter_unesc_multi(inkey):
    old = ""
    unesc = inkey
    # can sometimes run forever, limit rounds
    c = 0
    while "\\" in unesc and unesc != old and c <= 10:
        old = unesc
        unesc = unesc.encode().decode("unicode_escape", errors="ignore")
        c += 1
    return unesc


def filter_html(inkey):
    html = bs4.BeautifulSoup(inkey, "lxml")
    return html.get_text()


# Filter characters that should not appear in a PEM structure
# and spaces at beginning and end of lines.
# (Could make sense to always apply this after other filters...?)
def filter_nopem(inkey):
    key = re.sub(r"[^0-9A-Za-z \n=+/-]", "", inkey)
    key = re.sub(r"^ *", "", key, flags=re.MULTILINE)
    key = re.sub(r" *$", "", key, flags=re.MULTILINE)
    key = re.sub(r"KEY-----([^\n])", r"KEY-----\n\1", key)
    key = re.sub(r"([^\n])-----END", r"\1\n-----END", key)
    return re.sub(r"\n+", r"\n", key, flags=re.MULTILINE)


def filter_unesc_nopem(inkey):
    key = filter_unesc_multi(inkey)
    return filter_nopem(key)


kfilters = [
    filter_none,
    filter_unesc,
    filter_unesc_multi,
    filter_html,
    filter_nopem,
    filter_unesc_nopem,
]


def findkeys(data, perr=None, usebk=False, verbose=False):
    pkeys = rex.findall(data.decode(errors="ignore"))
    ckeys = []
    for pkey in pkeys:

        phash = hashlib.sha256(pkey.encode()).digest()
        shortphash = binascii.hexlify(phash).decode()[0:16]
        if phash in pdups:
            if verbose:
                print(f"Duplicate candidate {shortphash}")
            continue
        pdups.add(phash)

        ckey = None
        for kfilter in kfilters:
            bkey = kfilter(pkey).encode()
            try:
                if b"-----BEGIN OPENSSH PRIVATE KEY-----" in bkey:
                    ckey = serialization.load_ssh_private_key(bkey, password=None)
                else:
                    ckey = serialization.load_pem_private_key(bkey, password=None)
            # ValueError: various key parsing issues
            # TypeError: missing password
            # UnsupportedAlgorithm: unusual curves etc. (e.g. secp224k1)
            except (ValueError, TypeError, UnsupportedAlgorithm):
                continue
            ckeys.append(ckey)
            break
        if not ckey:
            if perr:
                if not os.path.isdir(perr):
                    os.makedirs(perr)
                fn = f"{perr}/{binascii.hexlify(phash).decode()}"
                with open(fn, "w") as f:
                    f.write(pkey)
                if verbose:
                    print(f"Wrote unparsable candidate {fn}")
            elif verbose:
                print(f"Unparsable candidate {shortphash}")

    # check for binary keys
    # TODO: find keys at arbitrary point in files
    if data[0:2] == b"\x30\x82":
        # looks like PKCS #1 or PKCS #8
        try:
            dkey = serialization.load_der_private_key(data, password=None)
            ckeys.append(dkey)
        except (ValueError, TypeError, UnsupportedAlgorithm):
            pass

    akeys = {}
    for ckey in ckeys:
        spki = ckey.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        spkisha256 = hashlib.sha256(spki).digest()
        shorthash = binascii.hexlify(spkisha256).decode()[0:16]
        if spkisha256 in dups:
            if verbose:
                print(f"Duplicate {shorthash}")
            continue
        dups.add(spkisha256)
        try:
            xkey = ckey.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        except ValueError:
            xkey = ckey.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        xkey = xkey.decode()
        if usebk and badkeys.checkprivkey(xkey)["results"] != {}:
            if verbose:
                print(f"badkeys detection, skipping {shorthash}")
            continue
        if verbose:
            print(f"Found key {shorthash}")
        akeys[spkisha256] = xkey
    return akeys


def writekey(key, fn, path, spki):
    if not os.path.isdir(path):
        os.makedirs(path)
    suffix = base64.urlsafe_b64encode(spki).decode()[0:3]
    fp = f"{path}/{fn}.{suffix}.key"
    if os.path.exists(fp):
        emsg = f"file {fp} already exists"
        raise OSError(emsg)
    with open(fp, "w") as f:
        f.write(key)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("input", nargs="+")
    ap.add_argument("-o", "--outdir")
    ap.add_argument("-p", "--parseerr", help="Output dir for unparsable candidates")
    ap.add_argument("-u", "--url", action="store_true", help="URL instead of dir")
    ap.add_argument("--nobadkeys", action="store_true", help="Don't check with badkeys")
    ap.add_argument("-D", "--dupfile", help="Store duplicate information")
    ap.add_argument("-q", "--quiet", action="store_true")
    args = ap.parse_args()

    if args.nobadkeys:
        usebk = False
    verbose = not args.quiet

    if not args.outdir:
        print("WARNING: No outdir given, will not write keys")

    # Prevents BeautifulSoup warnings, e.g., when content only
    # contains a single URL or a filename.
    warnings.filterwarnings("ignore", category=bs4.MarkupResemblesLocatorWarning)
    # Disable TLS certificate verification warning.
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    if args.dupfile and os.path.exists(args.dupfile):
        with open(args.dupfile, "rb") as f:
            pswitch = False
            while d := f.read(32):
                if d == b"\x00" * 32:
                    pswitch = True
                elif not pswitch:
                    dups.add(d)
                else:
                    pdups.add(d)

    if args.url:
        for url in args.input:
            if verbose:
                print(f"Checking {url}")
            host = urllib.parse.urlparse(url).netloc
            today = datetime.datetime.now(tz=datetime.timezone.utc).date().isoformat()
            meta = f"url: {url}\ndate: {today}\n\n"
            try:
                r = requests.get(url, timeout=60, verify=False)
            except requests.exceptions.ConnectionError:
                print(f"Connection error with {url}")
                continue
            keys = findkeys(r.content, perr=args.parseerr, usebk=usebk, verbose=verbose)
            if not args.outdir:
                continue
            for spki, k in keys.items():
                writekey(meta + k, host, args.outdir, spki)

    else:
        for path in args.input:
            if not os.path.isdir(path):
                sys.exit(f"ERROR: {path} is not a directory")
            for root, _, files in os.walk(path):
                for fn in files:
                    if not os.path.isfile(f"{root}/{fn}"):
                        continue
                    try:
                        with open(f"{root}/{fn}", "rb") as f:
                            content = f.read()
                    except FileNotFoundError:  # likely broken symlink
                        continue
                    keys = findkeys(content, perr=args.parseerr, usebk=usebk,
                                    verbose=verbose)
                    if not args.outdir:
                        continue
                    for spki, k in keys.items():
                        ofn = fn
                        if ofn.endswith(".key"):
                            ofn = ofn[0:-4]
                        writekey(k, ofn, args.outdir, spki)

    if args.dupfile:
        with open(args.dupfile, "wb") as f:
            for khash in sorted(dups):
                f.write(khash)
            f.write(b"\x00" * 32)
            for phash in sorted(pdups):
                f.write(phash)
