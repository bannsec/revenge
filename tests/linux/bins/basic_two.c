
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

float f = 4.1251;
double d = 10.4421;

int32_t i32 = 1337;


int32_t func() {
    return 31337;
}

int main() {
    i32 = func();
    printf("%d DONE\n", i32);
    return 0;
}
