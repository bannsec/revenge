
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>


void do_good() {
    printf("Good\n");
}

void do_access_violation() {
    int x[1];
    printf("%d", x[0x123123123]);
}

void do_access_read_violation() {
    // Attempt to load from memory 0x666
#if __amd64__
    __asm ("add 0x666,%rax");
#else
    __asm ("add 0x666,%eax");
#endif

}

void do_access_write_violation() {
    // Attempt to write to memory 0x666
#if __amd64__
    __asm ("movq %rax, (0x666)");
#else
    __asm ("mov  %eax, (0x666)");
#endif
}

void do_access_exec_violation() {
    // Attempt to execute from 0x666
#if __amd64__
    __asm ("mov $0x666, %rax;"
            "jmp %rax");
#else
    __asm ("mov $0x666, %eax;"
            "jmp %eax");
#endif
}

int do_abort() {
    return raise(SIGABRT);
}

int do_ill() {
    return raise(SIGILL);
}

void do_int3() {
    __asm("int $0x3;");
}

int do_sigsys() {
    return raise(SIGSYS);
}

// TODO: Test this... Right now, frida will hang on catching the exception, then the script will timeout and return
// The second time it's run, it will come back correctly. Probably a bug...
// Also, process exit will hang due to some part of this bug.
void do_overflow(char *s) {
    char vuln[4];
    strcpy(vuln, s); 
}

void do_arithmetic() {
#if __amd64__
    __asm ("xor %rax, %rax;" 
           "div %rax");
#else
    __asm ("xor %eax, %eax;" 
           "div %eax");
#endif
}

int main() {
    printf("Main");
}
