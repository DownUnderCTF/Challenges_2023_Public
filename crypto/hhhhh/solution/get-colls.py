import os
from tqdm import tqdm

"""
based on https://gist.github.com/DavidBuchanan314/a15e93eeaaad977a0fec3a6232c0b8ae
fastcoll binary is compiled from https://github.com/brimstone/fastcoll
"""

prefix = b'a' * 128
f2_a = b""
f2_b = b""

for _ in tqdm(range(128)):
	with open("prefix.bin", "wb") as pf:
		pf.write(prefix)
	os.system("rm -f prefix_msg*.bin && ./fastcoll -p prefix.bin")
	coll_a = open("prefix_msg1.bin", "rb").read()[-128:]
	coll_b = open("prefix_msg2.bin", "rb").read()[-128:]
	f2_a += coll_a
	f2_b += coll_b
	prefix += coll_a

with open("f2a.bin", "wb") as f:
	f.write(f2_a)
with open("f2b.bin", "wb") as f:
	f.write(f2_b)
