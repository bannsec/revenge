
#include <stdio.h>
#include <stdlib.h>

char **echo_argv(char **argv) {
    for (int i=0; argv[i] != 0; i++)
        puts(argv[i]);
    return argv;
}

char **echo_envp(char **envp) {
    for (int i=0; envp[i] != 0; i++)
        puts(envp[i]);
    return envp;
}

int echo_argc(int argc) {
    printf("argc: %d\n", argc);
    return argc;
}

void done() {
    return;
}

int main(int argc, char **argv, char **envp) {
    echo_argc(argc);
    echo_argv(argv);
    echo_envp(envp);
    
    done();
    return 0;
}
