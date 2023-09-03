from tqdm import tqdm
import subprocess
import itertools
import re
from string import ascii_letters, digits
alphabet = ascii_letters + digits + '{}_'

"""
We can see that the checker does a check based on the
output of an operation performed on two characters at a time.
In the ith iteration, the characters chosen are the ones at
index i and 25-i (i.e. outwards in, pairwise). The checker performs
a loop which runs for (inp[i] * inp[25-i]) % 256 iterations.
If the check is wrong, the program immediately exits. So we
can bruteforce two characters at a time and count the cpu
instructions to verify the guess. Since the number of iterations
in the inner loop is based on the two input chars, we can
use this as follows:
    When trying to verify a guess (a, b) for the ith and (25-i)th
    chars, we count the instructions when run with the two inputs
        ...aO...Qb...
        ...a0...pb...
    note that O*Q = 255 (mod 256) and 0*p = 0 (mod 256). So, if
    the guess is correct, the counts for these two inputs will
    differ by a fixed known amount (which can be determined by
    using the known first and last char of flag format).
If we already know some flag characters (i.e. flag format or guessing
based on previously found characters on the flag, the bruteforce
can be sped up to only need to bruteforce one of the characters).
"""

def ins_count(inp):
    while True:
        r = subprocess.run('perf stat -e instructions:u ../publish/sideways ' + inp, shell=True, capture_output=True).stderr.decode()
        c = re.findall(r'\s*(.*)\s*instructions:u', r)[0].replace(',', '')
        if c == '<not counted>':
            continue
        return int(c)

def brute_solve(known, pos):
    have_partial = len(known) == pos + 1 and known[pos][1] == None
    assert len(known) == pos or have_partial
    inp = list('?' * 26)
    for i, (a, b) in enumerate(known):
        inp[i] = a
        inp[26-i-1] = b

    res = []
    alphabet1 = known[pos][0] if have_partial else alphabet
    alphabet2 = alphabet
    for a, b in tqdm(list(itertools.product(alphabet1, alphabet2))):
        inp[pos] = a
        inp[26-pos-1] = b

        assert ord('O') * ord('Q') % 256 == 255
        inp[pos+1] = 'O'
        inp[26-(pos+1)-1] = 'Q'
        c1 = ins_count(''.join(inp))

        assert ord('0') * ord('p') % 256 == 0
        inp[pos+1] = '0'
        inp[26-(pos+1)-1] = 'p'
        c2 = ins_count(''.join(inp))

        diff = abs(abs(c1 - c2) - 145000)
        res.append((diff, (a, b)))

    return sorted(res)[0][1]

# save progress and guess and check here
known_already = {
    0: ('D', '}'),
    1: ('U', None),
    2: ('C', None),
    3: ('T', None),
    4: ('F', None),
    5: ('{', None)
}
known = []
for i in range(13):
    if i in known_already:
        if known_already[i][1] is not None:
            good = known_already[i]
        else:
            good = brute_solve(known + [known_already[i]], i)
    else:
        good = brute_solve(known, i)
    known.append(good)
    flag = list('?' * 26)
    for j, (a, b) in enumerate(known):
        flag[j] = a
        flag[26-j-1] = b
    print(''.join(flag))
