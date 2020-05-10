
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int8_t i8 = -13;
uint8_t ui8 = 13;

int16_t i16 = -1337;
uint16_t ui16 = 1337;

int32_t i32 = -1337;
uint32_t ui32 = 1337;

int64_t i64 = -1337;
uint64_t ui64 = 1337;


int func() {
    return 12;
}

int main() {

    char my_string[] = "This is my string";
    printf("%s\n", my_string);

    printf("i8: 0x%p\n", &i8);
    printf("ui8: 0x%p\n", &ui8);
    printf("i16: 0x%p\n", &i16);
    printf("ui16: 0x%p\n", &ui16);
    printf("i32: 0x%p\n", &i32);
    printf("ui32: 0x%p\n", &ui32);
    printf("i64: 0x%p\n", &i64);
    printf("ui64: 0x%p\n", &ui64);
    printf("func: 0x%p\n", &func);

    return 0;
}
