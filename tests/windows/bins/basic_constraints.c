#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
    char magic[] = "31337 \xba\xb3";
    char buf[64] = {0};

    puts("Enter the magic value!");
    fgets(buf, sizeof(magic), stdin);

    if ( strncmp(magic, buf, sizeof(magic)) == 0 ) {
        puts("Success 1!");
    } else {
        puts("Fail 1!");
    }

    puts("Enter another magic value");
    magic[1] += 2;
    
    fgets(buf, sizeof(magic), stdin);

    if ( strncmp(magic, buf, sizeof(magic)) == 0 ) {
        puts("Success 2!");
    } else {
        puts("Fail 2!");
    }

}
