#!/usr/bin/python3

import argparse
import base64
import binascii
import datetime
import hashlib
import json
import os
import pathlib
import re
import sys
import urllib.parse
import xml.etree.ElementTree

import lxml.etree
import lxml.html
import requests
import urllib3
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import (dsa, ec, ed448, ed25519,
                                                       rsa, x448, x25519)

havebk = True
try:
    import badkeys
except ImportError:
    havebk = False

rex_t = b"-----BEGIN[A-Z ]{0,20} PRIVATE KEY-----.{1,10000}?-----END[A-Z ]{0,20} PRIVATE KEY-----"
rex = re.compile(rex_t, flags=re.MULTILINE | re.DOTALL)

# regexp for JSON Web Keys (JWK)
jrex_t = b'{[^{}]{0,10000}"kty"[^}]{1,10000}}'
jrex = re.compile(jrex_t, flags=re.MULTILINE | re.DOTALL)

xrex_t = b"(?=(<(?:RSAKeyPair|RSAKeyValue).{1,10000}?</(?:RSAKeyPair|RSAKeyValue)>))"
xrex = re.compile(xrex_t, flags=re.MULTILINE | re.DOTALL)

DEFAULTUA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
             "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.3")

DNSPRE = "Private-key-format:"
DNSPRE_B = b"Private-key-format:"

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
        enctmp = unesc.encode(errors="replace")
        unesc = enctmp.decode("unicode_escape", errors="replace")
        c += 1
    return unesc


def filter_html(inkey):
    return lxml.html.document_fromstring(inkey.encode()).text_content()


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
        except (binascii.Error, ValueError):
            # binascii.Error caused by invalid base64
            # ValueError caused by non-ASCII characters
            return False
        try:
            key = makersa(n, e, d)
        except ValueError:
            # caused by invalid RSA values
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
    phash = hashlib.sha256(fragment).digest()
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
        pathlib.Path(fn).write_text(fragment, encoding="ascii", errors="replace")
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
    # JSON Web Keys use urlsafe base64 without padding,
    # therefore, we have to fix the padding first
    fb64 = b64.replace(" ", "").encode()
    pad = b"=" * ((-len(fb64)) % 4)
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
        if not all(isinstance(j[x], str) for x in ["n", "d", "e"]):
            return False
        try:
            n = ub64toint(j["n"])
            e = ub64toint(j["e"])
            d = ub64toint(j["d"])
            return makersa(n, e, d)
        except ValueError:
            return False
    # y value does not exist for all curve types, and
    # we do not need it, so ignore
    if {"x", "d", "crv"} <= j.keys():
        if not all(isinstance(j[x], str) for x in ["x", "d", "crv"]):
            return False
        if j["crv"] in ["Ed25519", "X25519", "Ed448", "X448"]:
            try:
                d = ub64tobin(j["d"])
                x = ub64tobin(j["x"])
            except binascii.Error:
                return False
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

        try:
            d = ub64toint(j["d"])
            x = ub64toint(j["x"])
        except (binascii.Error, ValueError):
            # Probably a Python bug that we need to catch ValueError here:
            # https://github.com/python/cpython/issues/129505
            return False
        if d == 0:
            return False
        if j["crv"] == "P-256":
            curve = ec.SECP256R1()
        elif j["crv"] == "P-384":
            curve = ec.SECP384R1()
        elif j["crv"] == "P-521":
            curve = ec.SECP521R1()
        else:
            return False
        try:
            eckey = ec.derive_private_key(d, curve)
        except ValueError:
            return False
        nums = eckey.public_key().public_numbers()
        if nums.x != x:
            return False
        return eckey
    return False


# Supports XKMS 2.0, XKMS draft version, .NET XML keys
def getxmlkey(kstr):
    # remove draft-style namespaces
    xkstr = kstr.replace("ds:", "")
    try:
        tree = xml.etree.ElementTree.fromstring(xkstr)
    except xml.etree.ElementTree.ParseError:
        return None
    n = tree.find("{*}Modulus")
    e = tree.find("{*}Exponent")
    d = tree.find("{*}D")
    # try draft-style names
    if e is None:
        e = tree.find("{*}PublicExponent")
    if d is None:
        d = tree.find("{*}PrivateExponent")
    if None in [n, d, e]:
        return None
    n = n.text.replace(" ", "").replace("\n", "").replace("\r", "")
    e = e.text.replace(" ", "").replace("\n", "").replace("\r", "")
    d = d.text.replace(" ", "").replace("\n", "").replace("\r", "")
    try:
        n = int.from_bytes(base64.b64decode(n), byteorder="big")
        e = int.from_bytes(base64.b64decode(e), byteorder="big")
        d = int.from_bytes(base64.b64decode(d), byteorder="big")
    except (binascii.Error, ValueError):
        return None
    try:
        return makersa(n, e, d)
    except ValueError:
        # Invalid RSA values
        return None


def puttympi(b64in):  # FIXME testen mit allen truncated values
    try:
        raw = base64.b64decode(b64in.encode())
    except binascii.Error:
        return None

    i = 0
    vals = []
    while i < len(raw):
        mlen = int.from_bytes(raw[i : i + 4], "big")
        i += 4
        vals.append(raw[i : i + mlen])
        i += mlen
    return vals


def getputtykey(kstr):
    klines = kstr.split("\n")
    public_offset = private_offset = None
    for i, xline in enumerate(klines):
        line = xline.strip()
        if line.startswith("Public-Lines:"):
            num = line.split(" ")[-1]
            try:
                public_len = int(num)
            except ValueError:
                return None
            public_offset = i + 1
        elif line.startswith("Private-Lines:"):
            num = line.split(" ")[-1]
            try:
                private_len = int(num)
            except ValueError:
                return None
            private_offset = i + 1
        if public_offset and private_offset:
            break
    if not public_offset or not private_offset:
        return None
    pubnum = "".join(klines[public_offset:public_offset + public_len])
    pubval = puttympi(pubnum)
    privnum = "".join(klines[private_offset:private_offset + private_len])
    privval = puttympi(privnum)
    if not pubval or not privval:
        return None
    if pubval[0] == b"ssh-rsa":
        e = int.from_bytes(pubval[1], "big")
        n = int.from_bytes(pubval[2], "big")
        d = int.from_bytes(privval[0], "big")
        try:
            return makersa(n, e, d)
        except ValueError:
            return None
    curve = None
    if pubval[0] == b"ecdsa-sha2-nistp256":
        curve = ec.SECP256R1()
    elif pubval[0] == b"ecdsa-sha2-nistp384":
        curve = ec.SECP384R1()
    elif pubval[0] == b"ecdsa-sha2-nistp521":
        curve = ec.SECP521R1()
    if curve:
        d = int.from_bytes(privval[0], "big")
        try:
            return ec.derive_private_key(d, ec.SECP256R1())
        except ValueError:
            return None

    if pubval[0] == b"ssh-dss":
        if len(pubval) < 5:
            return None
        p = int.from_bytes(pubval[1], "big")
        q = int.from_bytes(pubval[2], "big")
        g = int.from_bytes(pubval[3], "big")
        y = int.from_bytes(pubval[4], "big")
        x = int.from_bytes(privval[0], "big")
        try:
            dsaparams = dsa.DSAParameterNumbers(p, q, g)
            dsapub = dsa.DSAPublicNumbers(y, dsaparams)
            dsapriv = dsa.DSAPrivateNumbers(x, dsapub)
            return dsapriv.private_key()
        except ValueError:
            return None

    if pubval[0] == b"ssh-ed25519":
        if len(privval[0]) != 32:
            return None
        return ed25519.Ed25519PrivateKey.from_private_bytes(privval[0])
    if pubval[0] == b"ssh-ed448":
        if len(privval[0]) != 57:
            return None
        return ed448.Ed448PrivateKey.from_private_bytes(privval[0])

    # algorithm not yet supported or unknown
    return None


def findkeys(data, perr=None, usebk=False, verbose=False):
    ckeys = []

    if b"PRIVATE KEY-----" in data:
        pkeys = rex.findall(data)
        for pkey_b in pkeys:
            pkey = pkey_b.decode(errors="replace")
            phash = checkphash(pkey_b, verbose=verbose)
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

    if b'"kty"' in data:
        jkeys = jrex.findall(data)
        for jkey_b in jkeys:
            jkey = jkey_b.decode(errors="replace")
            phash = checkphash(jkey_b, verbose=verbose)
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

    if b"<RSAKeyPair" in data or b"<RSAKeyValue" in data:
        xkeys = xrex.findall(data)
        for xkey_b in xkeys:
            xkey = xkey_b.decode(errors="replace")
            phash = checkphash(xkey_b, verbose=verbose)
            if not phash:
                continue

            for kfilter in kfilters:
                xfkey = kfilter(xkey)
                ckey = getxmlkey(xfkey)
                if ckey:
                    ckeys.append(ckey)
                    break
            if not ckey:
                writeperr(perr, xkey, phash, verbose=verbose)

    if DNSPRE_B in data:
        dkeys = data.split(DNSPRE_B)
        for keyfrag in dkeys[1:]:
            dkey_b = DNSPRE_B + keyfrag[0:10000]
            dkey = dkey_b.decode(errors="replace")
            phash = checkphash(dkey_b, verbose=verbose)
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

    if b"PuTTY-User-Key-File-" in data:
        pkeys = data.split(b"PuTTY-User-Key-File-")
        for keyfrag in pkeys[1:]:
            pkey_b = b"PuTTY-User-Key-File-" + keyfrag[0:10000]
            pkey = pkey_b.decode(errors="replace")
            phash = checkphash(pkey_b, verbose=verbose)
            if not phash:
                continue

            for kfilter in kfilters:
                pfkey = kfilter(pkey)
                ckey = getputtykey(pfkey)
                if ckey:
                    ckeys.append(ckey)
                    break
            if not ckey:
                writeperr(perr, pkey, phash, verbose=verbose)

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
        if isinstance(ckey, rsa.RSAPrivateKey) and ckey.key_size > 5000:
            # skip very large RSA keys
            continue
        if isinstance(ckey, (ec.EllipticCurvePrivateKey, dsa.DSAPrivateKey)):
            # skip invalid DSA/ECDSA keys
            if isinstance(ckey, ec.EllipticCurvePrivateKey):
                alg = ec.ECDSA(hashes.SHA256())
            else:
                alg = hashes.SHA256()
            try:
                sig = ckey.sign(b"2u_Yg7", alg)
                ckey.public_key().verify(sig, b"2u_Yg7", alg)
            except (ValueError, InvalidSignature):
                continue

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
    if b"<!DOCTYPE html" in data or b"<html" in data or b"<HTML" in data:
        try:
            h2txt = lxml.html.document_fromstring(data).text_content().encode()
        except lxml.etree.ParserError:
            pass
        except UnicodeDecodeError:  # can happen with invalid charset metadata
            pass
        else:
            akeys |= findkeys(h2txt, perr=perr, usebk=usebk, verbose=verbose)

    return akeys


def writekey(key, fn, path, spki):
    if not os.path.isdir(path):
        os.makedirs(path)
    suffix = base64.urlsafe_b64encode(spki).decode()[0:5]
    # avoid problematic filenames
    ffn = re.sub(r"(^[.-]|[^A-Za-z0-9._-])", "_", fn)
    fp = f"{path}/{ffn}.{suffix}.key"
    if os.path.exists(fp):
        emsg = f"file {fp} already exists"
        raise OSError(emsg)
    pathlib.Path(fp).write_text(key, encoding="ascii")


def findinfile(fp, outdir, parseerr, usebk, verbose):
    content = pathlib.Path(f"{fp}").read_bytes()
    keys = findkeys(content, perr=parseerr, usebk=usebk, verbose=verbose)
    if not outdir:
        return
    for spki, k in keys.items():
        ofn = fp.split("/")[-1]
        if ofn.endswith(".key"):
            ofn = ofn[0:-4]
        writekey(k, ofn, outdir, spki)


def load_dupfile(dupfile):
    with open(dupfile, "rb") as f:
        pswitch = False
        while d := f.read(32):
            if d == b"\x00" * 32:
                pswitch = True
            elif not pswitch:
                dups.add(d)
            else:
                pdups.add(d)


def write_dupfile(dupfile):
    with open(dupfile, "wb") as f:
        for khash in sorted(dups):
            f.write(khash)
        f.write(b"\x00" * 32)
        for phash in sorted(pdups):
            f.write(phash)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("input", nargs="+")
    ap.add_argument("-o", "--outdir")
    ap.add_argument("-p", "--parseerr", help="Output dir for unparsable candidates")
    ap.add_argument("-u", "--url", action="store_true", help="URL instead of dir/file")
    ap.add_argument("--nobadkeys", action="store_true", help="Don't check with badkeys")
    ap.add_argument("-D", "--dupfile", help="Store duplicate information")
    ap.add_argument("-q", "--quiet", action="store_true")
    ap.add_argument("--useragent", help="User agent for URL mode")
    args = ap.parse_args()

    if not havebk and not args.nobadkeys:
        sys.exit("ERROR: badkeys not available (you may use --nobadkeys)")
    usebk = not args.nobadkeys

    verbose = not args.quiet

    if not args.outdir:
        print("WARNING: No outdir given, will not write keys")

    # Disable TLS certificate verification warning.
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    if args.dupfile and os.path.exists(args.dupfile):
        load_dupfile(args.dupfile)

    if args.url:
        if args.useragent:
            rheaders = {"User-Agent": args.useragent}
        else:
            rheaders = {"User-Agent": DEFAULTUA}
        for url in args.input:
            if verbose:
                print(f"Checking {url}")
            host = urllib.parse.urlparse(url).netloc
            today = datetime.datetime.now(tz=datetime.UTC).date().isoformat()
            meta = f"url: {url}\ndate: {today}\n\n"
            try:
                r = requests.get(url, timeout=60, verify=False, headers=rheaders)
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
            if os.path.isfile(path):
                findinfile(path, args.outdir, args.parseerr, usebk, verbose)
                continue
            if not os.path.isdir(path):
                sys.exit(f"ERROR: {path} is not a file or directory")
            for p, _, files in os.walk(path):
                for fn in files:
                    if not os.path.isfile(f"{p}/{fn}"):
                        continue
                    findinfile(f"{p}/{fn}", args.outdir, args.parseerr, usebk, verbose)

    if args.dupfile:
        write_dupfile(args.dupfile)
