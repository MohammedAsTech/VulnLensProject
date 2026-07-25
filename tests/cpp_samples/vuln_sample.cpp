// C++ sample for VulnLens (Phase 6). Each bad line has a safe counterpart.
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <string>

void copy_input(char* input) {
    char buf[10];
    strcpy(buf, input);                 // BAD: buffer overflow (CWE-120)
}

void copy_input_safe(char* input) {
    char buf[10];
    strncpy(buf, input, sizeof(buf));   // SAFE: bounded copy
}

void run_command(char* input) {
    system(input);                      // BAD: command injection (CWE-78)
}

void log_message(char* input) {
    printf(input);                      // BAD: format string (CWE-134)
    printf("%s", input);                // SAFE: literal format string
}

int make_token() {
    return rand();                      // BAD: weak randomness (CWE-330)
}
