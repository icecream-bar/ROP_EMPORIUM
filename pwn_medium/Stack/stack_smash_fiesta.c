#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Hidden function that prints the flag.
void win() {
    printf("\nCongratulations! You've triggered the hidden function.\n");
    printf("Flag: FLAG{buffer_overflow_success}\n");
    exit(0);
}

// Vulnerable function with a buffer overflow vulnerability.
void vuln() {
    char buffer[64];  // Fixed size buffer.
    printf("Enter your input: ");
    // Unsafe function that does not perform bounds checking.
    gets(buffer);
    printf("You entered: %s\n", buffer);
}

int main(int argc, char **argv) {
    // Disable buffering for stdout.
    setbuf(stdout, NULL);
    
    printf("Welcome to the buffer overflow challenge!\n");
    vuln();
    
    printf("Normal execution flow.\n");
    return 0;
}
