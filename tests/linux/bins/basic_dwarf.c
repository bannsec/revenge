#include <stdio.h>
#include <string.h>

void func1() {
    puts("func1");
}

int func2(char *thing) {
    puts(thing);
}

int main(int argc, char **argv) {

    if ( argc < 2 ) {
        puts("Try more args.");
    } else {
        if ( ! strcmp( argv[1], "win" ) ) {
            puts("Win.");
        }
    }
}
