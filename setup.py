from setuptools import setup, Extension, find_packages

# #This might not be needed. Find out whether to just use .so or not.
# secp256k1 = Extension(
    # 'keccak.sha3',
    # sources=['lib/sha3.c'],
    # depends=['lib/compiler.h', 'lib/sha3.h'],
    # extra_compile_args=["-Isrc/", "-std=gnu99", "-Wall"]
# )


setup(
    name="pysecp256k1",
    version='0.0.1',
    description="secp256k1 wrapped with cffi to use with python",
    author="Jacob Stenum Czepluch",
    author_email="j.czepluch@gmail.com",
    url="https://github.com/czepluch/pysecp256k1",
    license="MIT",
    packages=find_packages(exclude=["_cffi_build", "_cffi_build/*"]),
    ext_modules=[sha3],
    install_requires=["cffi>=1.2.1"],
    setup_requires=["cffi>=1.2.1"],
    cffi_modules=["_cffi_build/secp256k1_build.py:ffi"],
    classifiers=[
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: Implementation :: PyPy"
    ],
    zip_safe=False
)
