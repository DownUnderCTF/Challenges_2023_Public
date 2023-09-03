from string import printable

chars = '.=w-o^*'
flag_art = open('../publish/output.txt', 'r').read()
art = flag_art.replace('\n', '').replace(' ', '')

lookup_table = {}
for c in printable.encode():
    s = ''.join(chars[c % m] for m in [2, 3, 5, 7])
    lookup_table[s] = chr(c)

parts = [art[i:i+4] for i in range(0, len(art), 4)]
message = ''
for C in parts:
    message += lookup_table[C]

print(message)
