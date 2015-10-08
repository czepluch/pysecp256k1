clean: clean-build clean-pyc

clean-build:
	rm -fr build/
	rm -fr dist/
	rm -fr *.egg-info
	rm -fr c_secp256k1/*.so
	rm -fr c_secp256k1/_c_secp256k1.py
	rm -rf bitcoin-secp256k1-*
	rm secp256k1.tar.gz

clean-pyc:
	find . -name '*.pyc' -exec rm -f {} +
	find . -name '*.pyo' -exec rm -f {} +
	find . -name '*~' -exec rm -f {} +
	find . -name '__pycache__' -exec rm -fr {} +

test:
	py.test 
