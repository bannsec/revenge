
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int8_t i8 = -13;
u_int8_t ui8 = 13;

int16_t i16 = -1337;
u_int16_t ui16 = 1337;

int32_t i32 = -1337;
u_int32_t ui32 = 1337;

int64_t i64 = -1337;
u_int64_t ui64 = 1337;


int func() {
    return 12;
}

int main() {

    char *my_string = "This is my string";
    printf("%s %d DONE\n", my_string, func());

    return 0;
}
