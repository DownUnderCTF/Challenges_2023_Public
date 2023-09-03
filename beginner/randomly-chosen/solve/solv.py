import random

output = open('../publish/output.txt', 'r').read().strip()
flag_len = len(output) // 5
for seed in range(1337):
    random.seed(seed)
    choices = random.choices(list(range(flag_len)), k=len(output))
    flag = [''] * len(output)
    for i, v in enumerate(choices):
        flag[v] = output[i]
    flag = ''.join(flag)
    if flag.startswith('DUCTF'):
        print(flag)
