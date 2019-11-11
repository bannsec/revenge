#include <stdio.h>
#include <stdlib.h>

char *decode_flag(char *flag) {
    for ( int i=0; i < 15; i++ ) {
        flag[i] ^= 0x11;
    }
    return flag;
}

int main(int argc, char **argv) {
    char flag[] = "BdatcB\"rcteW}Qv";

    decode_flag(flag);
}
