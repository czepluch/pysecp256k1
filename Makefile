help:
	@echo "clean - remove all build, test, coverage and Python artifacts"
	@echo "clean-build - remove build artifacts"
	@echo "clean-pyc - remove Python file artifacts"
	@echo "clean-test - remove test and coverage artifacts"
	@echo "test - run tests quickly with the default Python"
	@echo "test-all - run tests on every Python version with tox"
	@echo "release - package and upload a release"
	@echo "install - install the package to the active Python's site-packages"

clean: clean-build clean-pyc

clean-build:
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info
	rm -rf c_secp256k1/*.so
	rm -rf c_secp256k1/*.dylib
	rm -rf c_secp256k1/*.dll
	rm -rf c_secp256k1/*.pyd
	rm -rf c_secp256k1/_c_secp256k1.py
	rm -rf lib-secp256k1

clean-pyc:
	find . -name '*.pyc' -exec rm -f {} +
	find . -name '*.pyo' -exec rm -f {} +
	find . -name '*~' -exec rm -f {} +
	find . -name '__pycache__' -exec rm -fr {} +

clean-test:
	rm -rf .tox/

test:
	cd tests; py.test

release: clean
	python setup.py sdist bdist_wheel upload

install: clean
	python setup.py install
