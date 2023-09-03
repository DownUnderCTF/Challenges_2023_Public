#include <stdio.h>
#include <ctype.h>

const char* sum = "{ arg1: 7664, arg2: 1337}";

void win() {
    system("/bin/sh");
}

void calculate() {
    size_t arg1;
    size_t arg2;
    sscanf(sum, "{ arg1: %d, arg2: %d}", &arg1, &arg2);
    size_t result = arg1 + arg2;

    printf("The result of the sum is: %d, it's over 9000!\n", result);

    if (result == 13370166083584009001) {
        printf("That is over 9000 indeed, how did you do that?\n");
        win();
    }
}

void leave_review() {
    char buf[0x30];
    printf("Enjoyed our calculator? Leave a review! : ");
    scanf("%48[ -~]", buf);
}

int main() {
    int choice;
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    printf("1. Use the safe calculator\n");
    printf("2. Review the safe calculator\n");
    while(1){
        printf("> ");
        scanf("%d", &choice);
        getchar();
        switch (choice) {
            case 1: 
                calculate();
                break;
            case 2:
                leave_review();
                break;
            default:
                return;
        }
    }
}
