chars = '.=w-o^*'
flag_art = open('../publish/output.txt', 'r').read()
art = flag_art.replace('\n', '').replace(' ', '')
parts = [art[i:i+4] for i in range(0, len(art), 4)]

flag = ''
for C in parts:
    c = crt([chars.index(c) for c in C], [2, 3, 5, 7])
    flag += chr(c)

print(flag)
