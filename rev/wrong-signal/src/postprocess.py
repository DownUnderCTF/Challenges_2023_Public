import lief
import re

binary = lief.parse('./wrong-signal-pre')

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

start_ptr = 0x13370000

for q in re.findall(r'#+|[se ]+', maze):
	print(repr(q))
	segment           = lief.ELF.Segment()
	if '#' not in q: segment.add(lief.ELF.SEGMENT_FLAGS.R)
	segment.type      = lief.ELF.SEGMENT_TYPES.LOAD
	segment.virtual_size   = 0x1000 * len(q)
	segment.content = [0] * 0x1000 * len(q)
	segment.alignment = 0x1000
	segment.virtual_address = start_ptr
	print('adding', hex(start_ptr), len(q))
	binary.add(segment)
	start_ptr += 0x1000 * len(q)

print('start', hex(0x13370000 + maze.index('s') * 0x1000))
print('end', hex(0x13370000 + maze.index('e') * 0x1000))
binary.write('./wrong-signal')