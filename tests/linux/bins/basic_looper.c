#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int value = 0;

int func() {
    return 1;
}

int main() {
    
    while ( 1 ) {
        value = func();
        usleep(100000);
    }
}
