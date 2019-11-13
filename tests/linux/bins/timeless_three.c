#include <stdio.h>
#include <stdlib.h>

long val = 12345;
long *val_p = &val;

int main(int argc, char **argv) {
    char str1[] = "Test string";
    char *str_p[1];

    str_p[0] = str1;

#if __amd64__
    __asm ( "movb $0x42, (%0);"
            "movb $0x75, 1(%0);"
            "mov  $2, %%r15;"
            "movb $0x6e, (%0, %%r15);"
            "movb $0x47, 2(%0, %%r15, 4);"
            :
            : "r" (str1), "r" (str1), "r" (str_p)
            :
            );

    __asm ( "movq $1337,  (%2);"
            "movq $7331, 0x601030;" 
            :
            : "r" (val), "r" (&val), "r" (val_p)
            :
            );
#elif __i386__
    __asm ( "mov $1,  %%eax;"
            "mov $2,  %%ebx;"
            "mov $3,  %%ecx;"
            "mov $4,  %%edx;"
            "mov $5,  %%edi;"
            "mov $6,  %%esi;"
            :
            : "r" (str1), "r" (str2), "r" (&str1)
            :
            );
#endif

}
