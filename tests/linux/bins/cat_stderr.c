#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {

    char buf[128] = {};

    if ( argc > 1 ) {
        fprintf(stderr, "%s", argv[1]);
    }
    
    else {
        while ( 1 ) {
            fgets(buf, sizeof(buf), stdin);
            fprintf(stderr, "%s", buf);
        }
    }
}
