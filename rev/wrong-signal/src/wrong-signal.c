#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define FLAG_SZ 16

void oops(int sig)
{
    puts("Wrong!");
    _exit(0);
}

char mangle_buf[FLAG_SZ] = {0xc2, 0xea, 0x96, 0xb6, 0xc, 0x9c, 0x92, 0xe5, 0x72, 0xff, 0xe9, 0x3d, 0x11, 0x54, 0xc1, 0x9f};

int main(void) {
    // Handle SIGSEGV
    struct sigaction sa;
    memset (&sa, '\0', sizeof(sa));
    sa.sa_sigaction = &oops;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGSEGV, &sa, NULL);

    char input_buf[FLAG_SZ];

    // Read input
    puts("Enter the password:");
    read(0, input_buf, FLAG_SZ);

    // Do magic
    unsigned char *start = (unsigned char *) 0x13386000;

    for (int i = 0; i < FLAG_SZ * 4; i++) {
        int dir = ((input_buf[i / 4] ^ mangle_buf[i / 4]) >> (i % 4 * 2)) & 0x3;
        switch(dir) {
            case 0: 
                start -= 0x1000 * 21;
                break;
            case 1:
                start -= 0x1000 *  1;
                break;
            case 2:
                start += 0x1000 *  1;
                break;
            case 3:
                start += 0x1000 * 21;
                break;
        }
        volatile unsigned char q = *start;
    }

    if (start == (unsigned char *) 0x13398000) {
        puts("Well done! Wrap that in DUCTF{}.");
    }
    else {
        oops(0);
    }
    
    return 0;
}