
char string1[] = "This is a test";
char *string2 = "This is a test";

char *string1_ptr = string1;
char **string2_ptr = &string2;

char *string3_uninit_ptr;
int random_int = 1337;
int *random_int_ptr = &random_int;
float floater = 12.123;
float *floater_ptr = &floater;

int main() {
    char stack_string[] = "This is a stack string.";
    char *stack_string_ptr = stack_string;
    string3_uninit_ptr = stack_string_ptr;

}

void *pointer_to_main = &main;
