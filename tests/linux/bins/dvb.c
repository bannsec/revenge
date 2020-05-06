#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <malloc.h>
#include <string.h>
#include <sys/mman.h>

/*
 * Damn Vulnerable Binary
 *
 * Author: Michael Bann
 * 
 * The purpose of this binary is to be a playground for different techniques and ways to break a binary. It's vulnerable in many ways and attempts to allow the user to simplify what they're working on or make it harder if they choose.
 */

void print_menu() {
    puts("Damn Vulnerable Binary");
    puts("----------------------");
    puts("0) Exit");
    puts("1) Stack Overflow");
    puts("2) Resolve Symbol Location");
    puts("3) Format String Attack");
    puts("4) Malloc");
    puts("5) Free");
    puts("6) Read Bytes");
    puts("7) Write Bytes");
    puts("8) Run shellcode");
    printf("?> ");

    // mmap
}

void setup() {
    setbuf(stdin, 0);
    setbuf(stdout, 0);
}

void stack_overflow() {
    char buf[16] = {0};
    printf("I have allocated a buffer of size 16 bytes at address %p\n", &buf);
    printf("Gimme input: ");
    fgets(buf, 4096, stdin);
}

void clear_buffer() {
    int c; while ((c = getchar()) != EOF && c != '\n') ;
}

void resolve_symbol() {
    char name[4096] = {0};
    char *pos;

    printf("Symbol: ");
    fgets(name, sizeof(name), stdin);
    
    if ((pos=strchr(name, '\n')) != NULL) {
        *pos = '\0';
    }

    unsigned int *addr = dlsym(0, name);
    printf("Address: %p\n", addr);

}

void format_string() {

    char buf[4096] = {0};

    puts("Whatever you enter will be printed back to you as a format string.");
    printf("Input: ");

    fgets(buf, sizeof(buf), stdin);
    printf(buf);
}

void do_malloc() {

    size_t size;
    printf("Size in bytes: ");

    if ( scanf("%zu", &size) <= 0 ) {
        puts("Something went wrong...");
        return;
    }

    void *p = malloc(size);
    printf("Address: %p\n", p);
    printf("Usable size: %zu\n", malloc_usable_size(p));

}

void do_free() {
    size_t p;

    printf("Address in hex: ");

    if ( scanf("%zx", &p) <= 0 ) {
        puts("Something went wrong...");
        return;
    }

    free((void *)p);
}

void do_write() {

    size_t addr;
    unsigned char c;
    char bytes[4096] = {0};

    printf("Address in hex: ");

    if ( scanf("%zx", &addr) <= 0 ) {
        puts("Something went wrong...");
        return;
    }
    clear_buffer();

    printf("Bytes to write in hex: ");

    fgets(bytes, sizeof(bytes), stdin);

    // It's off by one since it contains the newline
    if ( strlen(bytes) % 2 != 1 ) {
        puts("Error: Odd length hex bytes.");
        return;
    }

    for (int i=0; i < strlen(bytes)-1; i += 2) {

        if ( sscanf(bytes+i, "%02hhx", &c) <= 0 ) {
            puts("Error reading in your bytes.");
            return;
        }
        
        *(unsigned char *)(addr + (i / 2)) = c;
    }
}

void do_read() {
    size_t addr;
    size_t num;

    printf("Address in hex: ");

    if ( scanf("%zx", &addr) <= 0 ) {
        puts("Something went wrong...");
        return;
    }

    printf("Number of bytes: ");

    if ( scanf("%zd", &num) <= 0 ) {
        puts("Something went wrong...");
        return;
    }

    while ( num > 0 ) {

        printf("%02x", *(unsigned char *)addr);
        addr++;
        num--;
    }

    puts("");
}

void run_shellcode() {
    unsigned char c;
    char bytes[0x400] = {0};

    void *shellcode = mmap(0, sizeof(bytes), PROT_EXEC|PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);

    printf("Enter shellcode as hex: ");

    fgets(bytes, sizeof(bytes), stdin);

    // It's off by one since it contains the newline
    if ( strlen(bytes) % 2 != 1 ) {
        puts("Error: Odd length hex bytes.");
        return;
    }

    for (int i=0; i < strlen(bytes)-1; i += 2) {

        if ( sscanf(bytes+i, "%02hhx", &c) <= 0 ) {
            puts("Error reading in your bytes.");
            return;
        }
        
        *(unsigned char *)(shellcode + (i / 2)) = c;
    }

    // Kick it off
    int (*code)() = (int(*)())shellcode;
    code();

    free(shellcode);
}

int main(int argc, char **argv, char **envp) {

    int choice = -1;

    setup();

    while ( 1 ) {
        print_menu();

        if ( scanf("%d", &choice) <= 0 ) {
            puts("Something went wrong reading your value.");
            exit(1);
        }
        clear_buffer();

        switch ( choice ) {
            case 0:
                return 0;
            case 1:
                stack_overflow();
                break;
            case 2:
                resolve_symbol();
                break;
            case 3:
                format_string();
                break;
            case 4:
                do_malloc();
                break;
            case 5:
                do_free();
                break;
            case 6:
                do_read();
                break;
            case 7:
                do_write();
                break;
            case 8:
                run_shellcode();
                break;
            default:
                puts("Invalid option.");
                break;
        }
    }
}
