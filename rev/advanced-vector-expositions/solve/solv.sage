A = [[202, 163, 202, 209], [174, 192, 4, 158], [163, 166, 173, 28], [164, 71, 12, 121]]
B = [[67, 179, 65, 81], [143, 85, 122, 152], [166, 9, 164, 172], [229, 188, 132, 154]]
C = [[214, 11, 115, 105], [235, 214, 230, 42], [98, 39, 2, 233], [245, 188, 4, 12]]
W = [[48, 137, 221, 237], [202, 32, 84, 224], [16, 184, 215, 110], [11, 228, 224, 92]]
BASE0 = [[23, 116, 107, 137], [55, 206, 120, 132], [45, 163, 18, 104], [222, 243, 65, 66]]
BASE1 = [[76, 44, 178, 28], [15, 250, 228, 140], [68, 166, 19, 235], [233, 18, 122, 80]]
BASE2 = [[240, 174, 82, 48], [165, 241, 121, 236], [171, 169, 200, 66], [140, 103, 130, 173]]
BASE3 = [[7, 230, 19, 243], [2, 233, 123, 44], [63, 31, 204, 171], [140, 41, 121, 37]]
BASE4 = [[30, 91, 122, 24], [232, 103, 150, 124], [250, 150, 28, 33], [222, 100, 37, 142]]
BASE5 = [[195, 121, 56, 176], [57, 145, 151, 98], [244, 86, 181, 44], [132, 43, 45, 177]]
BASE6 = [[227, 245, 157, 227], [113, 79, 139, 194], [37, 70, 180, 28], [174, 159, 49, 40]]
BASE7 = [[212, 199, 198, 30], [188, 149, 201, 195], [210, 174, 50, 64], [29, 220, 41, 103]]
BASE8 = [[7, 37, 193, 179], [46, 47, 55, 232], [147, 122, 101, 233], [133, 73, 84, 72]]
BASE9 = [[182, 189, 244, 203], [134, 234, 196, 91], [145, 207, 130, 83], [40, 163, 68, 127]]
BASE10 = [[127, 87, 19, 2], [52, 71, 84, 192], [57, 179, 120, 196], [98, 47, 65, 124]]
BASE11 = [[167, 235, 59, 54], [89, 233, 94, 214], [74, 85, 145, 101], [180, 240, 60, 30]]
BASE12 = [[214, 158, 82, 86], [179, 33, 120, 0], [235, 38, 131, 122], [166, 195, 112, 171]]
BASE13 = [[127, 225, 175, 149], [101, 73, 241, 151], [133, 39, 203, 146], [211, 88, 213, 46]]
BASE14 = [[249, 195, 76, 73], [1, 63, 61, 149], [45, 229, 248, 94], [162, 196, 158, 215]]
BASE15 = [[176, 123, 142, 237], [81, 241, 234, 211], [118, 80, 96, 227], [99, 138, 60, 63]]
bases = [BASE0, BASE1, BASE2, BASE3, BASE4, BASE5, BASE6, BASE7, BASE8, BASE9, BASE10, BASE11, BASE12, BASE13, BASE14, BASE15]

def vectorize(M):
    return vector(sum(map(list, M.columns()), []))

def unvectorize(v):
    n = int(sqrt(len(list(v))))
    return Matrix([v[i:i+n] for i in range(0, n*n, n)]).T

F = GF(251)
A = Matrix(F, A)
B = Matrix(F, B)
C = Matrix(F, C)
I = Matrix.identity(F, 4)
bases = [Matrix(F, b) for b in bases]

L = I.tensor_product(A) + B.T.tensor_product(I)
X = unvectorize(L.solve_right(vectorize(C)))
v_bases = [vectorize(b) for b in bases]
cs = Matrix(v_bases).T.solve_right(vectorize(X))

print(cs)

"""
wwwwwwwwwwwww4wwwwww
wwwww3wwwwwwwwwwwwww
ww3wwwwwwwwwww8ww1ww
wwwwwwwwwwwwwwwwwwww
wwwwwwww2wwwwwwwwwww
wwwwwwwwwwwwwwwww7ww
wwww6wwwwwwwwwwwwwww
wwwwwwwwwwwwwwwwwwww
wwwwww5wwwwwwwwwwwww
wwwwwwwwww8wwww7wwww
wwwwwwwwwwwwwwwwwwww
w3wwwwwwwwwwwwwwwwww
wwwwwwwwww5wwwwwwwww
wwwwwwwwwwwwwwwwwwww
wwwwwwwwwwwwwwwwwwww
wwwwwwwwwwww9wwwwwww
wwwwwwwwwwwwwwwwwwww
www2wwwwwwwwwwwwwwww
wwwwwwwwFwwwwww0wwww
wwwwwwww^wwwwwwwwwww

DUCTF{m4ppy_m4tr1x_avx}
"""
