from distutils import log
from distutils.file_util import copy_file
from glob import glob
import os
import shutil
import tarfile
from cStringIO import StringIO
from setuptools import setup, find_packages
from urllib2 import urlopen, URLError
from setuptools.command.sdist import sdist
from setuptools.command.test import test as TestCommand
from distutils.command.build_ext import build_ext as distutils_build_ext
from setuptools.dist import Distribution


PACKAGE_NAME = "c_secp256k1"

TARBALL_URL = "https://github.com/bitcoin/secp256k1/tarball/c98df263edcef836a229745320c0718d550975f9"

LIB_SECP256K1_DIR = "lib-secp256k1"


class PyTest(TestCommand):

    def finalize_options(self):
        TestCommand.finalize_options(self)
        self.test_args = []
        self.test_suite = True

    def run_tests(self):
        # import here, cause outside the eggs aren't loaded
        self.spawn(['tox'])

test_requirements = ["pytest>=2.8.0", "tox>=2.1.1"]


def download_library(command):
    if command.dry_run:
        return
    if os.path.exists(os.path.join(LIB_SECP256K1_DIR, "Makefile")):
        # Library directory has been used. Throw away.
        shutil.rmtree(LIB_SECP256K1_DIR)
    if not os.path.exists(LIB_SECP256K1_DIR):
        command.announce("downloading secp256k1 library", level=log.INFO)
        try:
            r = urlopen(TARBALL_URL)
            if r.getcode() == 200:
                content = StringIO(r.read())
                content.seek(0)
                with tarfile.open(fileobj=content) as tf:
                    dirname = tf.getnames()[0].partition('/')[0]
                    tf.extractall()
                shutil.move(dirname, LIB_SECP256K1_DIR)
            else:
                raise SystemExit("Unable to download secp256k1 library: HTTP-Status: %d", r.getcode())
        except URLError as ex:
            raise SystemExit("Unable to download secp256k1 library: %s", ex.message)


class SDist(sdist):
    def run(self):
        download_library(self)
        sdist.run(self)


class BuildExt(distutils_build_ext):
    def run(self):
        # Normally the library should have been downloaded during `sdist`.
        # In case of `develop` however this might not have happened.
        download_library(self)

        self.build_library()
        distutils_build_ext.run(self)

    def build_library(self):
        self.announce("building secp256k1 library", level=log.INFO)
        self.spawn(['sh', '-c', 'cd {libdir}; ./autogen.sh'])
        self.spawn(['sh', '-c', 'cd {libdir}; ./configure --enable-shared --enable-module-recovery'])
        self.spawn(['sh', '-c', 'cd {libdir}; make'])
        if not self.dry_run:
            lib = next(
                lib
                for lib in glob(os.path.join(LIB_SECP256K1_DIR, ".libs", "libsecp256k1*"))
                if lib.rpartition('.')[2] in ('so', 'dylib', 'dll', 'pyd')
            )
            build_py = self.get_finalized_command('build_py')
            dst = os.path.join(
                os.path.join(
                    build_py.build_lib,
                    build_py.get_package_dir(PACKAGE_NAME)
                ),
                os.path.basename(lib)
            )
            copy_file(lib, dst, verbose=self.verbose, dry_run=self.dry_run)

    def spawn(self, cmd, search_path=1, level=1):
        cmd = [c.format(libdir=LIB_SECP256K1_DIR) for c in cmd]
        distutils_build_ext.spawn(self, cmd, search_path, level)


class HasExtensionsDistribution(Distribution):
    def has_ext_modules(self):
        # Even though we don't use the regular setuptools extension
        # mechanism we want setuptools to think so because we need to
        # build platform specific wheels.
        return True


setup(
    name=PACKAGE_NAME,
    version='0.0.8',
    description="secp256k1 wrapped with cffi to use with python",
    author="Jacob Stenum Czepluch",
    author_email="j.czepluch@gmail.com",
    url="https://github.com/czepluch/pysecp256k1",
    license="MIT",
    packages=find_packages(exclude=["_cffi_build", "_cffi_build/*"]),
    package_data={'': ['libsecp256k1.*']},
    install_requires=["cffi>=1.2.1", "bitcoin>=1.1.36"],
    setup_requires=["cffi>=1.2.1"],
    cffi_modules=["_cffi_build/c_secp256k1_build.py:ffi"],
    classifiers=[
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: Implementation :: PyPy"
    ],
    cmdclass={
        'sdist': SDist,
        'build_ext': BuildExt,
        'test': PyTest
    },
    distclass=HasExtensionsDistribution,
    ext_modules=[],  # Don't remove. This is needed to generate correct wheels.
    tests_require=test_requirements,
    zip_safe=False,
)
