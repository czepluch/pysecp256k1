from glob import glob
from os import path
obj_name = glob(path.abspath(path.join(path.dirname(__file__), "libsecp256k1*")))[0]
print(obj_name)
