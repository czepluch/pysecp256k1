import sys
from setuptools import setup, find_packages
from subprocess import call
from urllib2 import urlopen
from setuptools.command.test import test as TestCommand


class PyTest(TestCommand):

    def finalize_options(self):
        TestCommand.finalize_options(self)
        self.test_args = []
        self.test_suite = True

    def run_tests(self):
        # import here, cause outside the eggs aren't loaded
        import pytest
        pytest.main(self.test_args)

test_requirements = [
    "bitcoin>=1.1.36", "pytest>=2.8.0", "tox>=2.1.1"
]

#  Fetching the bitcoin_secp256k1 tarball from github and running build.sh if success
url = "https://github.com/bitcoin/secp256k1/tarball/master"
r = urlopen(url)
if r.getcode() == 200:
    open('secp256k1.tar.gz', 'wb').write(r.read())
    call("./build.sh", shell=True)
else:
    print("error while downloading " + url)
    print(r.getcode())
    sys.exit(1)

setup(
    name="c_secp256k1",
    version='0.0.1',
    description="secp256k1 wrapped with cffi to use with python",
    author="Jacob Stenum Czepluch",
    author_email="j.czepluch@gmail.com",
    url="https://github.com/czepluch/pysecp256k1",
    license="MIT",
    packages=find_packages(exclude=["_cffi_build", "_cffi_build/*"]),
    package_data={'': ['libsecp256k1.*']},
    install_requires=["cffi>=1.2.1"],
    setup_requires=["cffi>=1.2.1"],
    cffi_modules=["_cffi_build/c_secp256k1_build.py:ffi"],
    classifiers=[
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: Implementation :: PyPy"
    ],
    cmdclass={'test': PyTest},
    tests_require=test_requirements,
    zip_safe=False,

)
