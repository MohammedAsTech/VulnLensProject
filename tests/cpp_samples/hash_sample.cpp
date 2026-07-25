// Sample for cpp-weak-hash (Phase 6b). Mirrors tests/vulnerable_samples/hash_sample.py.
#include <openssl/md5.h>
#include <openssl/sha.h>

void hash_password(const unsigned char* data, size_t len, unsigned char* out) {
    MD5(data, len, out);      // BAD: MD5 is broken (CWE-327)
    SHA1(data, len, out);     // BAD: SHA1 is broken (CWE-327)
}
