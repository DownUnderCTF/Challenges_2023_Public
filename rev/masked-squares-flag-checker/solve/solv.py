from ortools.sat.python import cp_model

def uncompress_mask(c_mask):
    i = 0
    out = [[0] * 6 for _ in range(6)]
    curr_x, curr_y = 0, 0
    while True:
        v = c_mask[i]
        i += 1
        if v == 0:
            break
        if v > 0:
            z = 1
        else:
            z = 0
            v = -v
        for j in range(v):
            out[curr_y][curr_x] = z
            curr_x += 1
            if curr_x == 6:
                curr_x = 0
                curr_y += 1
    return out

def compute_masked_sum(square, mask):
    n = len(square)
    s = 0
    for i in range(n):
        for j in range(n):
            if mask[i][j]:
                s += square[i][j]
    return s

outputs = bytes.fromhex('a1050000fb070000eb040000ef07000007070000ea02000037000000aa050000cd050000520500006302000022050000660100002a070000dc0500004b050000db070000c607000093070000c607000016010000430700003f080000e605000078030000c8040000')
outputs = [int.from_bytes(outputs[i:i+4], 'little') for i in range(0, 26*4, 4)]
masks_bytes = list(bytes.fromhex('fb01fe01ff03fd02ff01ff01ff01ff02fd02fe0200000000ff01fd02fd02ff01fe03ff01ff07ff03ff02000000000000ff01ff01ff02ff01fa01ff01fe01ff01ff01fc03ff01fe0002ff05fd03ff04ff02ff05fd02fd00000000000000000000ff01fd01ff01fe01ff03ff01ff01fe05ff04ff01fd00000001fe02f801f902ff01fd01fe01fc00000000000000000000eb01f2000000000000000000000000000000000000000000fe03fc04fb01fe01ff01fe01fe01ff04ff00000000000000fc05fd01fb01fd01fe05fc02000000000000000000000000ff02fc01ff04fd01fc01ff02ff01fd01ff02fe0000000000fe01f801ff01fd01ff01f901f8000000000000000000000001fe05ff01f803fe01fe01fd01fc01000000000000000000fd01f701fe01ef01ff00000000000000000000000000000003fb04ff01fe01ff02fd03ff01ff03ff02ff000000000000fe02fd01ff01ff01ff01f901ff06ff03ff01ff000000000001fb01fe02ff02ff01ff01fb01ff01ff05fc00000000000002fd01fb04fe03fe05ff02ff02ff02000000000000000000ff01fd01ff02fe01ff07fe03ff04ff01fe01ff000000000002ff01fe02ff02fe05ff01ff02fd02ff01fe02ff0100000001fd03ff01fe01ff06ff01ff02fe01ff01ff03ff02000000f701f701fb01f6000000000000000000000000000000000001ff02fe01ff09ff01ff01f902fe01fe0100000000000000ff09ff03ff06ff01ff01fe01fd01fc000000000000000000fe01fd01ff02fb06ff02fe04ff01fc000000000000000000fe01fc01ff01fe01fd01fd01fd03fa01fe00000000000000f804fe02ff03fb01fe02ff01fc0000000000000000000000'))
compressed_masks = []
while len(masks_bytes):
    c_mask = []
    while True:
        v = masks_bytes.pop(0)
        if v == 0:
            c_mask.append(0)
            break
        if v > 128:
            c_mask.append(v - 256)
        else:
            c_mask.append(v)
    if len(c_mask) > 1:
        compressed_masks.append(c_mask)

model = cp_model.CpModel()
flag_chars = [model.NewIntVar(32, 126, f'f{i}') for i in range(36)]
flag_chars_square = [flag_chars[i:i+6] for i in range(0, len(flag_chars), 6)]
for i, kc in enumerate('DUCTF{'.encode()):
    model.Add(flag_chars[i] == kc)
model.Add(flag_chars[-1] == ord('}'))
for output, c_mask in zip(outputs, compressed_masks):
    mask = uncompress_mask(c_mask)
    v = compute_masked_sum(flag_chars_square, mask)
    model.Add(output == v)
solver = cp_model.CpSolver()
status = solver.Solve(model)
f = [solver.Value(flag_chars[i]) for i in range(36)]
print(bytes(f).decode())
