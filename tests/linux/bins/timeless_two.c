#include <stdio.h>
#include <stdlib.h>

char *str1 = "Test string";
char **str2 = &str1;

int some_call() {
    return 1337;
}

int main() {

#if __amd64__
    __asm ( "mov $1,  %%rax;"
            "mov $2,  %%rbx;"
            "mov $3,  %%rcx;"
            "mov $4,  %%rdx;"
            "mov $5,  %%rdi;"
            "mov $6,  %%rsi;"
            "mov $7,  %%r8;"
            "mov $8,  %%r9;"
            "mov $9,  %%r10;"
            "mov $10, %%r11;"
            "mov $11, %%r12;"
            "mov $12, %%r13;"
            "mov $13, %%r14;"
            "mov $14, %%r15;"
            :
            : "r" (str1), "r" (str2), "r" (&str1)
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

    return some_call();

}
