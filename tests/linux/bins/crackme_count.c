#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

bool win(char *guess) {

    if ( guess[0] != 'f' )
        return false;

    if ( guess[1] != 'l' )
        return false;

    if ( guess[2] != 'a' )
        return false;

    if ( guess[3] != 'g' )
        return false;
    
    if ( guess[4] != '\x00' )
        return false;

    return true;
}

int main(int argc, char **argv) {
    if ( win(argv[1]) == true )
        puts("Yay!");
    else
        puts("Boo!");
}
