#!/usr/bin/python3

import argparse
import base64
import binascii
import datetime
import hashlib
import json
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
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519
from cryptography.hazmat.primitives.asymmetric import rsa, x448, x25519

usebk = True
try:
    import badkeys
except ImportError:
    print("WARNING: Could not load badkeys, not checking for known keys")
    usebk = False

rex_t = r"-----BEGIN[A-Z ]* PRIVATE KEY-----.*?-----END[A-Z ]* PRIVATE KEY-----"
rex = re.compile(rex_t, flags=re.MULTILINE | re.DOTALL)

# regexp for JSON Web Keys (JWK)
jrex_t = r'{[^{}]*"kty"[^}]*}'
jrex = re.compile(jrex_t, flags=re.MULTILINE | re.DOTALL)

DNSPRE = "Private-key-format:"

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


def getdnsseckey(kstr):
    kdata = {}
    ikey = None
    # Skip first line ("Private-key-format:"), stop if seen again
    for kline in kstr.split("\n")[1:]:
        if kline.startswith(("Created", DNSPRE)):
            break
        if ":" in kline:
            ikey = kline.split(":", 1)[0].strip()
            if ikey in kdata:  # if we see same key multiple times, ignore it
                ikey = None
            kdata[ikey] = kline.split(":", 1)[1].strip()
        elif ikey:
            kdata[ikey] += kline.strip()

    # if it has a "Modulus", it is an RSA key
    if {"Modulus", "PublicExponent", "PrivateExponent"} <= kdata.keys():
        try:
            n = int.from_bytes(base64.b64decode(kdata["Modulus"]), byteorder="big")
            e = int.from_bytes(base64.b64decode(kdata["PublicExponent"]),
                               byteorder="big")
            d = int.from_bytes(base64.b64decode(kdata["PrivateExponent"]),
                               byteorder="big")
            key = makersa(n, e, d)
        except (ValueError, binascii.Error):
            # ValueError caused by invalid RSA values
            # binascii.Error caused by invalid base64
            return False
        return key

    if {"Algorithm", "PrivateKey"} <= kdata.keys():

        try:
            algid = int(kdata["Algorithm"].split(" ")[0])
            ecbin = base64.b64decode(kdata["PrivateKey"])
        except ValueError:  # non-numeric Algorithm or bad base64
            return False

        if algid == 13:
            if len(ecbin) > 32:
                return False
            ecval = int.from_bytes(ecbin, byteorder="big")
            return ec.derive_private_key(ecval, ec.SECP256R1())
        if algid == 14:
            if len(ecbin) > 48:
                return False
            ecval = int.from_bytes(ecbin, byteorder="big")
            return ec.derive_private_key(ecval, ec.SECP384R1())
        if algid == 15:
            if len(ecbin) != 32:
                return False
            return ed25519.Ed25519PrivateKey.from_private_bytes(ecbin)
        if algid == 16:
            if len(ecbin) != 57:
                return False
            return ed448.Ed448PrivateKey.from_private_bytes(ecbin)
    return False


def checkphash(fragment, verbose=True):
    phash = hashlib.sha256(fragment.encode()).digest()
    if phash in pdups:
        if verbose:
            short = binascii.hexlify(phash).decode()[0:16]
            print(f"Duplicate candidate {short}")
        return False
    pdups.add(phash)
    return phash


def writeperr(perr, fragment, phash, verbose=True):
    if perr:
        if not os.path.isdir(perr):
            os.makedirs(perr)
        fn = f"{perr}/{binascii.hexlify(phash).decode()}"
        with open(fn, "w", encoding="ascii", errors="ignore") as f:
            f.write(fragment)
    if verbose:
        short = binascii.hexlify(phash).decode()[0:16]
        print(f"Unparsable candidate {short}")


def makersa(n, e, d):
    p, q = rsa.rsa_recover_prime_factors(n, e, d)
    iqmp = rsa.rsa_crt_iqmp(p, q)
    dmp1 = rsa.rsa_crt_dmp1(d, p)
    dmq1 = rsa.rsa_crt_dmq1(d, q)
    pubnum = rsa.RSAPublicNumbers(e, n)
    privnum = rsa.RSAPrivateNumbers(p, q, d, dmp1, dmq1, iqmp, pubnum)
    return privnum.private_key()


def ub64tobin(b64):
    # convert urssafe base64 to int and fix padding first
    fb64 = b64.replace(" ", "")
    pad = "=" * ((-len(fb64)) % 4)
    return base64.urlsafe_b64decode(fb64 + pad)


def ub64toint(b64):
    raw = ub64tobin(b64)
    return int.from_bytes(raw, byteorder="big")


def getjwk(kstr):
    try:
        # RFC 7517 uses multiline base64 for values, standard JSON
        # cannot parse this, therefore, remove newlines
        j = json.loads(kstr.replace("\n", ""))
    except json.decoder.JSONDecodeError:
        return False
    if {"n", "e", "d"} <= j.keys():
        try:
            n = ub64toint(j["n"])
            e = ub64toint(j["e"])
            d = ub64toint(j["d"])
            return makersa(n, e, d)
        except ValueError as e:
            return False
    # y value does not exist for all curve types, and
    # we do not need it, so ignore
    if {"x", "d", "crv"} <= j.keys():
        if j["crv"] in ["Ed25519", "X25519", "Ed448", "X448"]:
            d = ub64tobin(j["d"])
            x = ub64tobin(j["x"])
            if j["crv"] == "Ed25519":
                if len(d) != 32:
                    return False
                key = ed25519.Ed25519PrivateKey.from_private_bytes(d)
            if j["crv"] == "X25519":
                if len(d) != 32:
                    return False
                key = x25519.X25519PrivateKey.from_private_bytes(d)
            if j["crv"] == "Ed448":
                if len(d) != 57:
                    return False
                key = ed448.Ed448PrivateKey.from_private_bytes(d)
            if j["crv"] == "X448":
                if len(d) != 56:
                    return False
                key = x448.X448PrivateKey.from_private_bytes(d)
            xb = key.public_key().public_bytes(encoding=serialization.Encoding.Raw,
                                               format=serialization.PublicFormat.Raw)
            if xb != x:
                return False
            return key

        d = ub64toint(j["d"])
        x = ub64toint(j["x"])
        if j["crv"] == "P-256":
            curve = ec.SECP256R1()
        elif j["crv"] == "P-384":
            curve = ec.SECP384R1()
        elif j["crv"] == "P-521":
            curve = ec.SECP521R1()
        else:
            return False
        eckey = ec.derive_private_key(d, curve)
        nums = eckey.public_key().public_numbers()
        if nums.x != x:
            return False
        return eckey
    return False


def findkeys(data, perr=None, usebk=False, verbose=False):
    datastr = data.decode(errors="replace", encoding="ascii")

    pkeys = rex.findall(datastr)
    ckeys = []
    for pkey in pkeys:
        phash = checkphash(pkey, verbose=verbose)
        if not phash:
            continue

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
            writeperr(perr, pkey, phash, verbose=verbose)

    jkeys = jrex.findall(datastr)
    for jkey in jkeys:
        phash = checkphash(jkey, verbose=verbose)
        if not phash:
            continue

        for kfilter in kfilters:
            jfkey = kfilter(jkey)
            ckey = getjwk(jfkey)
            if ckey:
                ckeys.append(ckey)
                break
        if not ckey:
            writeperr(perr, jkey, phash, verbose=verbose)

    if DNSPRE in datastr:
        dkeys = datastr.split(DNSPRE)
        for keyfrag in dkeys[1:]:
            dkey = DNSPRE + keyfrag
            phash = checkphash(dkey, verbose=verbose)
            if not phash:
                continue

            for kfilter in kfilters:
                dfkey = kfilter(dkey)
                ckey = getdnsseckey(dfkey)
                if ckey:
                    ckeys.append(ckey)
                    break
            if not ckey:
                writeperr(perr, dkey, phash, verbose=verbose)

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
    # avoid problematic filenames
    ffn = re.sub(r"(^[.-]|[^A-Za-z0-9._-])", "_", fn)
    fp = f"{path}/{ffn}.{suffix}.key"
    if os.path.exists(fp):
        emsg = f"file {fp} already exists"
        raise OSError(emsg)
    with open(fp, "w", encoding="ascii") as f:
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
            today = datetime.datetime.now(tz=datetime.UTC).date().isoformat()
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
