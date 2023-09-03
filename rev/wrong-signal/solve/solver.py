import sys

maze = """
#####################
#s    #            e#
##### ######## ######
#         #         #
######### #### ######
#          #        #
####### ########## ##
#        #      #   #
# ######### ### ### #
#             #     #
#####################
""".replace('\n','')

seen_pos = set()
soln = []
stack = [(maze.index('s'), [])]
while stack:
	pos, sofar = stack.pop(0)
	if pos in seen_pos:
		continue
	if maze[pos] == 'e':
		soln = sofar
		break
	for d in [-21, -1, 1, 21]:
		if 0 <= pos + d < len(maze) and maze[pos + d] != '#':
			stack.append((pos + d, sofar + [[-21, -1, 1, 21].index(d)]))
	seen_pos |= {pos}

print(soln, file=sys.stderr)

output = []
mangle_buf = [0xc2, 0xea, 0x96, 0xb6, 0xc, 0x9c, 0x92, 0xe5, 0x72, 0xff, 0xe9, 0x3d, 0x11, 0x54, 0xc1, 0x9f]
for b in range(16):
	o = 0
	for i in range(4):
		o |= soln[b * 4 + i] << (i * 2)
	output.append(o ^ mangle_buf[b])

"""
target = b'hElCYi8OxUF7PAA5'
for a, b in zip(output, target):
	print(hex(a ^ b), end=', ')
"""

print(bytes(output).decode())