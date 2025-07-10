During development, some bugs in Python and the Cryptography package were discovered.

Python
======

* [Use-after-free in unicode_escape decoder with error handler (CVE-2025-4516)](
  https://github.com/python/cpython/issues/133767)

Cryptography
============

Bugs:

* [Incorrect error message with invalid Ed448 keys](
  https://github.com/pyca/cryptography/pull/11880)
* [Invalid DSA key can cause cryptography.exceptions.InternalError / internal OpenSSL
  error](https://github.com/pyca/cryptography/issues/11920)
* [Importing openssh ecdsa-sk key results in unexpected AttributeError exception](
  https://github.com/pyca/cryptography/issues/12062)
* [Unexpected exception pyo3_runtime.PanicException with load_pem_private_key() and
  invalid EC key](https://github.com/pyca/cryptography/issues/12100)
* [Infinite loop in rsa_recover_prime_factors / reject d, e values <= 1](
  https://github.com/pyca/cryptography/pull/12272)
* [cryptography.exceptions.InternalError when importing malformed / too large ed25519
  key](https://github.com/pyca/cryptography/issues/12746)
* [Reject invalid values in various functions for partial RSA key recovery, avoid
  unexpected exceptions](https://github.com/pyca/cryptography/pull/13032)

Improvements / feature requests:

* [Speedup rsa_recover_prime_factors() by using random value](
  https://github.com/pyca/cryptography/pull/11899)
* [unsafe_skip_rsa_key_validation for load_ssh_private_key()](
  https://github.com/pyca/cryptography/issues/12307)
* [Inconsistency with password behavior between load_pem_private_key() and
  load_ssh_private_key()](https://github.com/pyca/cryptography/issues/12070)

All fixed in cryptography 45.0.0 and above.

binwalk
=======

* [PNG file causes hang / infinite loop](https://github.com/ReFirmLabs/binwalk/issues/877)
* [RAR file with password causes hang](https://github.com/ReFirmLabs/binwalk/issues/878)
