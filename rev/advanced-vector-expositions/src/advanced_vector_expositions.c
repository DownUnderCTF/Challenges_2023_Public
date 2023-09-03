#include <stdio.h>
#include <stdlib.h>
#include <err.h>
#include <errno.h>
#include <inttypes.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <linux/userfaultfd.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <poll.h>
#include <pthread.h>
#include <unistd.h>
#include <termios.h>
#include <immintrin.h>

#define MOD 251
#define N 20
#define N_marks 16

typedef union {
    float  f[4][4];
    __m256 n[2];
} matrix_t;

typedef struct {
    int x;
    int y;
} point_t;

typedef struct {
    point_t player; 
    point_t flag;
    char* book[N][N];
    matrix_t curr;
    int cs[16];
} state_t;

state_t state;
long uffds[N_marks];
point_t marks[N_marks] = {
    {13, 0},
    {5, 1},
    {2, 2},
    {14, 2},
    {17, 2},
    {8, 4},
    {17, 5},
    {4, 6},
    {6, 8},
    {10, 9},
    {15, 9},
    {1, 11},
    {10, 12},
    {12, 15},
    {3, 17},
    {15, 18}
};
const matrix_t A = { .f = {{202, 163, 202, 209}, {174, 192, 4, 158}, {163, 166, 173, 28}, {164, 71, 12, 121}} };
const matrix_t B = { .f = {{67, 179, 65, 81}, {143, 85, 122, 152}, {166, 9, 164, 172}, {229, 188, 132, 154}} };
const matrix_t C = { .f = {{214, 11, 115, 105}, {235, 214, 230, 42}, {98, 39, 2, 233}, {245, 188, 4, 12}} };
const matrix_t W = { .f = {{48, 137, 221, 237}, {202, 32, 84, 224}, {16, 184, 215, 110}, {11, 228, 224, 92}} };
const matrix_t BASE0 = { .f = {{23, 116, 107, 137}, {55, 206, 120, 132}, {45, 163, 18, 104}, {222, 243, 65, 66}} };
const matrix_t BASE1 = { .f = {{76, 44, 178, 28}, {15, 250, 228, 140}, {68, 166, 19, 235}, {233, 18, 122, 80}} };
const matrix_t BASE2 = { .f = {{240, 174, 82, 48}, {165, 241, 121, 236}, {171, 169, 200, 66}, {140, 103, 130, 173}} };
const matrix_t BASE3 = { .f = {{7, 230, 19, 243}, {2, 233, 123, 44}, {63, 31, 204, 171}, {140, 41, 121, 37}} };
const matrix_t BASE4 = { .f = {{30, 91, 122, 24}, {232, 103, 150, 124}, {250, 150, 28, 33}, {222, 100, 37, 142}} };
const matrix_t BASE5 = { .f = {{195, 121, 56, 176}, {57, 145, 151, 98}, {244, 86, 181, 44}, {132, 43, 45, 177}} };
const matrix_t BASE6 = { .f = {{227, 245, 157, 227}, {113, 79, 139, 194}, {37, 70, 180, 28}, {174, 159, 49, 40}} };
const matrix_t BASE7 = { .f = {{212, 199, 198, 30}, {188, 149, 201, 195}, {210, 174, 50, 64}, {29, 220, 41, 103}} };
const matrix_t BASE8 = { .f = {{7, 37, 193, 179}, {46, 47, 55, 232}, {147, 122, 101, 233}, {133, 73, 84, 72}} };
const matrix_t BASE9 = { .f = {{182, 189, 244, 203}, {134, 234, 196, 91}, {145, 207, 130, 83}, {40, 163, 68, 127}} };
const matrix_t BASE10 = { .f = {{127, 87, 19, 2}, {52, 71, 84, 192}, {57, 179, 120, 196}, {98, 47, 65, 124}} };
const matrix_t BASE11 = { .f = {{167, 235, 59, 54}, {89, 233, 94, 214}, {74, 85, 145, 101}, {180, 240, 60, 30}} };
const matrix_t BASE12 = { .f = {{214, 158, 82, 86}, {179, 33, 120, 0}, {235, 38, 131, 122}, {166, 195, 112, 171}} };
const matrix_t BASE13 = { .f = {{127, 225, 175, 149}, {101, 73, 241, 151}, {133, 39, 203, 146}, {211, 88, 213, 46}} };
const matrix_t BASE14 = { .f = {{249, 195, 76, 73}, {1, 63, 61, 149}, {45, 229, 248, 94}, {162, 196, 158, 215}} };
const matrix_t BASE15 = { .f = {{176, 123, 142, 237}, {81, 241, 234, 211}, {118, 80, 96, 227}, {99, 138, 60, 63}} };
matrix_t BASES[N_marks] = {BASE0, BASE1, BASE2, BASE3, BASE4, BASE5, BASE6, BASE7, BASE8, BASE9, BASE10, BASE11, BASE12, BASE13, BASE14, BASE15};

// https://stackoverflow.com/a/46058667
matrix_t matrix_multiply(matrix_t M1, matrix_t M2) {
    matrix_t mResult;
    __m256 a0, a1, b0, b1;
    __m256 c0, c1, c2, c3, c4, c5, c6, c7;
    __m256 t0, t1, u0, u1;

    t0 = M1.n[0];                                                   // t0 = a00, a01, a02, a03, a10, a11, a12, a13
    t1 = M1.n[1];                                                   // t1 = a20, a21, a22, a23, a30, a31, a32, a33
    u0 = M2.n[0];                                                   // u0 = b00, b01, b02, b03, b10, b11, b12, b13
    u1 = M2.n[1];                                                   // u1 = b20, b21, b22, b23, b30, b31, b32, b33

    a0 = _mm256_shuffle_ps(t0, t0, _MM_SHUFFLE(0, 0, 0, 0));        // a0 = a00, a00, a00, a00, a10, a10, a10, a10
    a1 = _mm256_shuffle_ps(t1, t1, _MM_SHUFFLE(0, 0, 0, 0));        // a1 = a20, a20, a20, a20, a30, a30, a30, a30
    b0 = _mm256_permute2f128_ps(u0, u0, 0x00);                      // b0 = b00, b01, b02, b03, b00, b01, b02, b03  
    c0 = _mm256_mul_ps(a0, b0);                                     // c0 = a00*b00  a00*b01  a00*b02  a00*b03  a10*b00  a10*b01  a10*b02  a10*b03
    c1 = _mm256_mul_ps(a1, b0);                                     // c1 = a20*b00  a20*b01  a20*b02  a20*b03  a30*b00  a30*b01  a30*b02  a30*b03

    a0 = _mm256_shuffle_ps(t0, t0, _MM_SHUFFLE(1, 1, 1, 1));        // a0 = a01, a01, a01, a01, a11, a11, a11, a11
    a1 = _mm256_shuffle_ps(t1, t1, _MM_SHUFFLE(1, 1, 1, 1));        // a1 = a21, a21, a21, a21, a31, a31, a31, a31
    b0 = _mm256_permute2f128_ps(u0, u0, 0x11);                      // b0 = b10, b11, b12, b13, b10, b11, b12, b13
    c2 = _mm256_mul_ps(a0, b0);                                     // c2 = a01*b10  a01*b11  a01*b12  a01*b13  a11*b10  a11*b11  a11*b12  a11*b13
    c3 = _mm256_mul_ps(a1, b0);                                     // c3 = a21*b10  a21*b11  a21*b12  a21*b13  a31*b10  a31*b11  a31*b12  a31*b13

    a0 = _mm256_shuffle_ps(t0, t0, _MM_SHUFFLE(2, 2, 2, 2));        // a0 = a02, a02, a02, a02, a12, a12, a12, a12
    a1 = _mm256_shuffle_ps(t1, t1, _MM_SHUFFLE(2, 2, 2, 2));        // a1 = a22, a22, a22, a22, a32, a32, a32, a32
    b1 = _mm256_permute2f128_ps(u1, u1, 0x00);                      // b0 = b20, b21, b22, b23, b20, b21, b22, b23
    c4 = _mm256_mul_ps(a0, b1);                                     // c4 = a02*b20  a02*b21  a02*b22  a02*b23  a12*b20  a12*b21  a12*b22  a12*b23
    c5 = _mm256_mul_ps(a1, b1);                                     // c5 = a22*b20  a22*b21  a22*b22  a22*b23  a32*b20  a32*b21  a32*b22  a32*b23

    a0 = _mm256_shuffle_ps(t0, t0, _MM_SHUFFLE(3, 3, 3, 3));        // a0 = a03, a03, a03, a03, a13, a13, a13, a13
    a1 = _mm256_shuffle_ps(t1, t1, _MM_SHUFFLE(3, 3, 3, 3));        // a1 = a23, a23, a23, a23, a33, a33, a33, a33
    b1 = _mm256_permute2f128_ps(u1, u1, 0x11);                      // b0 = b30, b31, b32, b33, b30, b31, b32, b33
    c6 = _mm256_mul_ps(a0, b1);                                     // c6 = a03*b30  a03*b31  a03*b32  a03*b33  a13*b30  a13*b31  a13*b32  a13*b33
    c7 = _mm256_mul_ps(a1, b1);                                     // c7 = a23*b30  a23*b31  a23*b32  a23*b33  a33*b30  a33*b31  a33*b32  a33*b33

    c0 = _mm256_add_ps(c0, c2);                                     // c0 = c0 + c2 (two terms, first two rows)
    c4 = _mm256_add_ps(c4, c6);                                     // c4 = c4 + c6 (the other two terms, first two rows)
    c1 = _mm256_add_ps(c1, c3);                                     // c1 = c1 + c3 (two terms, second two rows)
    c5 = _mm256_add_ps(c5, c7);                                     // c5 = c5 + c7 (the other two terms, second two rose)

    // Finally complete addition of all four terms and return the results
    mResult.n[0] = _mm256_add_ps(c0, c4);       // n0 = a00*b00+a01*b10+a02*b20+a03*b30  a00*b01+a01*b11+a02*b21+a03*b31  a00*b02+a01*b12+a02*b22+a03*b32  a00*b03+a01*b13+a02*b23+a03*b33
                                                //      a10*b00+a11*b10+a12*b20+a13*b30  a10*b01+a11*b11+a12*b21+a13*b31  a10*b02+a11*b12+a12*b22+a13*b32  a10*b03+a11*b13+a12*b23+a13*b33
    mResult.n[1] = _mm256_add_ps(c1, c5);       // n1 = a20*b00+a21*b10+a22*b20+a23*b30  a20*b01+a21*b11+a22*b21+a23*b31  a20*b02+a21*b12+a22*b22+a23*b32  a20*b03+a21*b13+a22*b23+a23*b33
                                                //      a30*b00+a31*b10+a32*b20+a33*b30  a30*b01+a31*b11+a32*b21+a33*b31  a30*b02+a31*b12+a32*b22+a33*b32  a30*b03+a31*b13+a32*b23+a33*b33

    for(int i = 0; i < 4; i++) {
        for(int j = 0; j < 4; j++) {
            mResult.f[i][j] = (float)((int)mResult.f[i][j] % MOD);
        }
    }

    return mResult;
}

matrix_t matrix_add(matrix_t M1, matrix_t M2) {
    matrix_t mResult;
    __m256 v0, v1;
    __m256 t0, t1, u0, u1;

    t0 = M1.n[0];
    t1 = M1.n[1];
    u0 = M2.n[0];
    u1 = M2.n[1];

    v0 = _mm256_add_ps(t0, u0);
    v1 = _mm256_add_ps(t1, u1);

    mResult.n[0] = v0;
    mResult.n[1] = v1;

    for(int i = 0; i < 4; i++) {
        for(int j = 0; j < 4; j++) {
            mResult.f[i][j] = (float)((int)mResult.f[i][j] % 251);
        }
    }

    return mResult;
}

int matrix_eq(matrix_t M1, matrix_t M2) {
    for(int i = 0; i < 4; i++) {
        for(int j = 0; j < 4; j++) {
            if(M1.f[i][j] != M2.f[i][j]) {
                return 0;
            }
        }
    }
    return 1;
}

int bookmark_idx(int x, int y) {
    for(int i = 0; i < N_marks; i++) {
        if(marks[i].x == x && marks[i].y == y) {
            return i;
        }
    }
    return -1;
}

void print_book(state_t* state) {
    for(int y = 0; y < N; y++) {
        for(int x = 0; x < N; x++) {
            if(state->player.x == x && state->player.y == y) {
                printf("^");
            } else {
                printf("%c", *(state->book[y][x]));
            }
        }
        printf("\n");
    }
    printf("\n");
}

static void* fault_handler_thread(void *arg) {
    struct pollfd pollfds[N_marks];
    static struct uffd_msg msg;

    for(int i = 0; i < N_marks; i++) {
        pollfds[i].fd = uffds[i];
        pollfds[i].events = POLLIN;
    }

    while(1) {
        if(poll(pollfds, N_marks, -1) == -1) {
            err(EXIT_FAILURE, "error");
        }

        for(int i = 0; i < N_marks; i++) {
            if(!(pollfds[i].revents & POLLIN)) {
                continue;
            }

            if(read(uffds[i], &msg, sizeof(msg)) == 0) {
                continue;
            }

           if(msg.arg.pagefault.flags & UFFD_PAGEFAULT_FLAG_WP) {
               state.curr = matrix_add(
                   state.curr,
                   matrix_add(
                       matrix_multiply(A, BASES[i]),
                       matrix_multiply(BASES[i], B)
                   )
               );
               state.cs[i] += 1;

               struct uffdio_writeprotect wp;
               wp.range.start = (long long)msg.arg.pagefault.address;
               wp.range.len = (long long)0x1000;
               wp.mode = 0;
               fflush(stdout);
               if(ioctl(uffds[i], UFFDIO_WRITEPROTECT, &wp) == -1)
                   err(EXIT_FAILURE, "error");
           }

        }
    }
}

int is_legal_move(state_t* state, char direction) {
    if(direction != 'h' && direction != 'j' && direction != 'k' && direction != 'l' && direction != 'm') return 0;
    int x = state->player.x;
    int y = state->player.y;
    if(x == 0 && direction == 'h') return 0;
    if(x == N - 1 && direction == 'l') return 0;
    if(y == 0 && direction == 'k') return 0;
    if(y == N - 1 && direction == 'j') return 0;
    if(y == 0 && direction == 'm') return 0;
    if(direction == 'm') {
        char above = *(state->book[y-1][x]);
        if(above == 'w') return 0;
    } else {
        if(direction == 'h') {
            char left = *(state->book[y][x-1]);
            if(left != 'w') return 0;
        }
        if(direction == 'l') {
            char left = *(state->book[y][x+1]);
            if(left != 'w') return 0;
        }
        if(direction == 'k') {
            char left = *(state->book[y-1][x]);
            if(left != 'w') return 0;
        }
        if(direction == 'j') {
            char left = *(state->book[y+1][x]);
            if(left != 'w') return 0;
        }
    }
    return 1;
}

point_t next_position(point_t curr, char direction) {
    switch(direction) {
        case 'h':
            return (point_t) { curr.x - 1, curr.y };
        case 'j':
            return (point_t) { curr.x, curr.y + 1 };
        case 'k':
            return (point_t) { curr.x, curr.y - 1 };
        case 'l':
            return (point_t) { curr.x + 1, curr.y };
    }
}

void mark(state_t* state) {
    int x = state->player.x;
    int y = state->player.y;
    int idx = bookmark_idx(x, y-1);
    char* above_addr = state->book[y-1][x];
    if(idx == -1) {
        if(matrix_eq(state->curr, C)) {
            matrix_t CS;
            for(int i = 0; i < 4; i++) {
                for(int j = 0; j < 4; j++) {
                    CS.f[i][j] = state->cs[4*i + j];
                }
            }
            matrix_t F = matrix_multiply(W, CS);
            printf("DUCTF{");
            for(int i = 0; i < 4; i++) {
                for(int j = 0; j < 4; j++) {
                    printf("%c", (char)F.f[i][j]);
                }
            }
            printf("}\n");
            exit(0);
        }
    } else {
        if(*above_addr == '9') return;
        *above_addr = *above_addr + 1;
        struct uffdio_writeprotect wp;
        wp.range.start = (unsigned long) above_addr;
        wp.range.len = 0x1000;
        wp.mode = UFFDIO_WRITEPROTECT_MODE_WP;
        if (ioctl(uffds[idx], UFFDIO_WRITEPROTECT, &wp) == -1)
            err(EXIT_FAILURE, "error");
    }
}

void move(state_t* state, char direction) {
    if(!is_legal_move(state, direction)) return;
    if(direction == 'm') {
        mark(state);
    } else {
        state->player = next_position(state->player, direction);
    }
}

int main() {
    state.player = (point_t) { 9, 1 };
    state.flag = (point_t) { 8, 18 };
    state.curr = (matrix_t) { .f = {{0, 0, 0, 0}, {0, 0, 0, 0}, {0, 0, 0, 0}, {0, 0, 0, 0}} };
    for(int i = 0; i < 16; i++) {
        state.cs[i] = 0;
    }

    // set up the pages
    for(int y = 0; y < N; y++) {
        for(int x = 0; x < N; x++) {
            state.book[y][x] = (char*)mmap(NULL, 1, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANON, -1, 0);
            if(bookmark_idx(x, y) >= 0) {
                *(state.book[y][x]) = '0';
            } else if(state.flag.x == x && state.flag.y == y) {
                *(state.book[y][x]) = 'F';
            } else {
                *(state.book[y][x]) = 'w';
            }
        }
    }

    // set up fault handlers
    for(int i = 0; i < N_marks; i++) {
        int uffd = syscall(SYS_userfaultfd, O_CLOEXEC | O_NONBLOCK);
        if (uffd == -1)
            err(EXIT_FAILURE, "error");

        struct uffdio_api       uffdio_api;
        uffdio_api.api = UFFD_API;
        uffdio_api.features = 0;
        if (ioctl(uffd, UFFDIO_API, &uffdio_api) == -1)
            err(EXIT_FAILURE, "error");

        struct uffdio_register uffdio_register;
        uffdio_register.range.start = (unsigned long) state.book[marks[i].y][marks[i].x];
        uffdio_register.range.len = 0x1000;
        uffdio_register.mode = UFFDIO_REGISTER_MODE_WP;
        if (ioctl(uffd, UFFDIO_REGISTER, &uffdio_register) == -1)
            err(EXIT_FAILURE, "error");

        struct uffdio_writeprotect wp;
        wp.range.start = (unsigned long) state.book[marks[i].y][marks[i].x];
        wp.range.len = 0x1000;
        wp.mode = UFFDIO_WRITEPROTECT_MODE_WP;
        if (ioctl(uffd, UFFDIO_WRITEPROTECT, &wp) == -1)
            err(EXIT_FAILURE, "error");

        uffds[i] = uffd;
    }

    pthread_t thr;
    if(pthread_create(&thr, NULL, fault_handler_thread, (void *) uffds) != 0) {
        err(EXIT_FAILURE, "error");
    }

    struct termios tty_attr;
     
	tcgetattr(0, &tty_attr);
	tty_attr.c_lflag &= (~(ICANON|ECHO));
	tty_attr.c_cc[VTIME] = 0;
	tty_attr.c_cc[VMIN] = 1;
	tcsetattr(0, TCSANOW, &tty_attr);

    while(1) {
        print_book(&state);

        char mvmt = getc(stdin);

        if(mvmt == 'q') break;

        move(&state, mvmt);
    }
}
