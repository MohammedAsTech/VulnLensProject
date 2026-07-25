// Sample for C++ taint analysis (Phase 6b). Mirrors tests/vulnerable_samples/taint_sample.py.
// Same dangerous sinks, but only some actually receive untrusted input.
#include <cstdlib>

void run_tainted(char* filename) {
    // TAINTED: the parameter flows straight into system()
    system(filename);
}

void run_constant() {
    // NOT tainted: a hardcoded command, no untrusted input
    system("ls -la");
}

void run_propagated(char* filename) {
    // TAINTED via propagation: taint flows param -> cmd -> system
    char* cmd = filename;
    system(cmd);
}
