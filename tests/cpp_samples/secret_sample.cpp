// Sample for cpp-hardcoded-secret (Phase 6b). Mirrors tests/vulnerable_samples/secret_sample.py.
#include <string>

void connect() {
    char* password = "hunter2";          // BAD: hardcoded secret (CWE-798)
}

void connect_from_env(char* password) {
    // SAFE: value comes from a parameter (e.g. loaded from the environment), not a literal
}
