#include "hash.h"

unsigned char* SSHA(const unsigned char* msg, size_t length) {
    unsigned char A, B, C, D, E; //Initial Seed Value
    A = 56;
    B = 99;
    C = 102;
    D = 67;
    E = 76;

    for (size_t i = 0; i < length; i++) {
        // One round per message byte, per the SSHA diagram. All five new values
        // are computed from the OLD A..E, so snapshot them first.
        unsigned char a = A, b = B, c = C, d = D, e = E;

        A = e;
        B = a;
        C = (unsigned char)((a >> 2) + e);
        D = (unsigned char)((a >> 2) ^ (b >> 1));
        E = (unsigned char)(msg[i] + (b >> 1) + ((b & c) | (d & c)));
    }

    unsigned char* digest = (unsigned char*)malloc(DIGEST_SIZE * sizeof(unsigned char));
    digest[0] = A;
    digest[1] = B;
    digest[2] = C;
    digest[3] = D;
    digest[4] = E;
    return digest;
}

int digest_equal(struct Digest digest1, struct Digest digest2) {
    return ((digest1.hash0 == digest2.hash0) &&
        (digest1.hash1 == digest2.hash1) &&
        (digest1.hash2 == digest2.hash2) &&
        (digest1.hash3 == digest2.hash3) &&
        (digest1.hash4 == digest2.hash4));
}

void printDigest(struct Digest digest) {
    printf("%d %d %d %d %d\n", digest.hash0, digest.hash1, digest.hash2, digest.hash3, digest.hash4);
}
