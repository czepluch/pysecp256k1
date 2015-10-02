from distutils.command.build import build
from setuptools import setup, find_packages
from subprocess import call

class BitcoinSecpBuild(build):
    def run(self):
        call("./build.sh", shell=True)


setup(
    name="pysecp256k1",
    version='0.0.1',
    description="secp256k1 wrapped with cffi to use with python",
    author="Jacob Stenum Czepluch",
    author_email="j.czepluch@gmail.com",
    url="https://github.com/czepluch/pysecp256k1",
    license="MIT",
    packages=find_packages(exclude=["_cffi_build", "_cffi_build/*"]),
    package_data={'': ['libsecp256k1.so']},
    install_requires=["cffi>=1.2.1"],
    setup_requires=["cffi>=1.2.1"],
    cffi_modules=["_cffi_build/secp256k1_build.py:ffi"],
    classifiers=[
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: Implementation :: PyPy"
    ],
    zip_safe=False,
    cmdclass={
        'build': BitcoinSecpBuild,
    }
)
