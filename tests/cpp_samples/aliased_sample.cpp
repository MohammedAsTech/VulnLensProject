// Sample for namespace-qualified calls (Phase 6b). Mirrors tests/vulnerable_samples/aliased_sample.py.
// A literal-name-only rule would miss this; name resolution should still catch it.
#include <cstdlib>

void run_qualified(char* cmd) {
    // BAD: system() called through the std:: namespace qualifier
    std::system(cmd);
}
