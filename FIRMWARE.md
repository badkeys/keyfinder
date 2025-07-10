The `tarfinder` script supports a parameter `--firmware` that will use [`binwalk`
](https://github.com/ReFirmLabs/binwalk) to recursively unpack firmware images.
`binwalk` uses various third-party tools to unpack a variety of firmware image types.

Due to the variety of tools used, there is a substantial risk of security issues. It may
be a advisable to use a dedicated user account.

Hangs / Infinite Loops
----------------------

Unfortunately, `binwalk` or the tools it calls commonly hang on some inputs. The
following workarounds help to avoid most hangs:

* Several hangs and infinite loops have been fixed in git after release 3.1.0 ([see
  also](https://github.com/ReFirmLabs/binwalk/issues/876)). Until a new version is
  released, `binwalk` should be compiled from its git repository. Some commandline
  parameters has also changed lately, `tarfinder` expects the git version.

* `sleuthkit` can hang on ISO files ([bug report](
  https://github.com/sleuthkit/sleuthkit/issues/3312)). As long as this is unfixed, I
  recommend deinstalling `sleuthkit`. (ISO images are still supported through other
  tools.)

Installing extraction tools in Gentoo
-------------------------------------

I am primarily running `keyfinder`/`tarfinder` on Gentoo systems. To increase input
format support, the following packages can be installed:

```
app-arch/7zip[symlink]
app-arch/cabextract
app-arch/cpio
app-arch/lz4
app-arch/lzop
app-arch/unrar
dev-embedded/srecord
dev-libs/ucl
dev-python/lz4
dev-python/zstandard
sys-apps/dtc
sys-fs/ubi_reader
sys-fs/yaffs2utils
```

As explained above, I currently do not recommend installation of `sleuthkit`.

Do not use `p7zip` (unmaintained), install `7zip` with the `symlink` use flag ([see
also](https://bugs.gentoo.org/942397)).

You should install at least `jefferson` and `uefi_firmware` from `pypi`/`pip` and make
sure they are in the PATH.

You can check [these scripts](
https://github.com/ReFirmLabs/binwalk/tree/master/dependencies) provided by `binwalk` to
learn about additional dependencies.

Furthermore, you should have `sasquatch` installed, a modified version of `unsquashfs`
from `squashfs-tools`. Unfortunately, the situation is rather confusing. There [exists a
version](https://github.com/onekey-sec/sasquatch) based on `squashfs-tools` 4.5, but it
does not support as many formats as the old version ([see also](
https://github.com/onekey-sec/sasquatch/issues/19).

The old version is provided as [a patch and build script](
https://github.com/devttys0/sasquatch) on top of `squashfs-tools` 4.3. But it requires
multiple bug fixes to compile with modern `gcc`. (I may provide more information later,
I managed to compile it with [this PR](https://github.com/devttys0/sasquatch/pull/47)
and an additional manual fix for some pointer issues.)
