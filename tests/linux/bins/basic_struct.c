
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

typedef struct MyStruct {
    double d;
    float f;
    int32_t i32;
    int8_t i8;
    int16_t i16;
    void *p;
} MyStruct;

int MyStructSizeOf = sizeof(MyStruct);

MyStruct MyStructInstance = { 1.234, 1.234, -55, 4, -17, (void *) 0x123456 };

MyStruct call_ret(MyStruct s) {
    return s;
}

double return_double(MyStruct *s) {
    return s->d;
}

float return_float(MyStruct *s) {
    return s->f;
}

int32_t return_i32(MyStruct *s) {
    return s->i32;
}

int8_t return_i8(MyStruct *s) {
    return s->i8;
}

int16_t return_i16(MyStruct *s) {
    return s->i16;
}

void * return_p(MyStruct *s) {
    return s->p;
}

int main() {
    MyStruct s = {};
    MyStruct s2;

    s2 = call_ret(s);
    return 0;
}
