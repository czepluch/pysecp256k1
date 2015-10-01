import os
from sys import platform
from distutils.command.build import build
from setuptools.command.install import install
from setuptools import setup, find_packages
from subprocess import call
from multiprocessing import cpu_count

BASEPATH = os.path.dirname(os.path.abspath(__file__))
SECP_PATH = os.path.join(BASEPATH, 'bitcoinSecp256k1')

class BitcoinSecpBuild(build):
    def run(self):
        build.run(self)

        #build bitcoinSecp256k1
        build_path = os.path.abspath(self.build_temp)

        cmd = [
                './autogen.sh',
                './configure --enable-shared --enable-module-recovery',
                'make',
                'OUT=' + build_path,
                'V=' + str(self.verbose),
            ]

        try:
            cmd.append('-j%d' % cpu_count())
        except NotImplementedError:
            print 'Unable to determine number of CPUs. Using single threaded make.'

        options = [
            'DEBUG=n',
            'ENABLE_SDL=n',
        ]
        cmd.extend(options)

        targets = ['python']
        cmd.extend(targets)

        if platform == 'darwin':
            target_path = 'OSX64_PYTHON'
        else:
            target_path = 'UNIX_PYTHON'

        # target_files = [os.path.join(build_path, target_path, '.lib', 'libsecp256k1.so')]

        def compile():
            call(cmd, cwd=SECP_PATH)

        self.execute(compile, [], 'Compiling bitcoin secp256k1')

        # copy resulting tool to library build folder
        self.mkpath(self.build_lib)

        # if not self.dry_run:
            # for target in target_files:
                # self.copy_file(target, self.build_lib)


class BitcoinSecpInstall(install):
    def initialize_options(self):
        install.initialize_options(self)
        self.build_scripts = None

    def finalize_options(self):
        install.finalize_options(self)
        self.set_undefined_options('build', ('build_scripts', 'build_scripts'))

    def run(self):
        # run original install code
        install.run(self)

        # install XCSoar executables
        self.copy_tree(self.build_lib, self.install_lib)


def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()


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
    # ext_modules=[sha3],
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
        'install': BitcoinSecpInstall,
    }
)
