#include <stdlib.h>
#include <stddef.h>

/* Seed values: I can't see the original function, so these are placeholders.
   They are the low bytes of the SHA-1 initial values. Replace them with your originals. */
#define SEED_A 0x01
#define SEED_B 0x89
#define SEED_C 0xFE
#define SEED_D 0x76
#define SEED_E 0xF0

unsigned char* SSHA2(const unsigned char* msg, size_t length) {
    if (msg == NULL && length > 0) return NULL;

    unsigned char* digest = malloc(5);
    if (digest == NULL) return NULL;

    unsigned char A = SEED_A, B = SEED_B, C = SEED_C, D = SEED_D, E = SEED_E;

    for (size_t i = 0; i < length; i++) {
        unsigned char a2 = (unsigned char)(A >> 2);
        unsigned char b1 = (unsigned char)(B >> 1);
        unsigned char mix = (unsigned char)((B & C) | (C & D));

        unsigned char newA = E;
        unsigned char newB = A;
        unsigned char newC = (unsigned char)(a2 + E);
        unsigned char newD = (unsigned char)(a2 ^ b1);
        unsigned char newE = (unsigned char)(b1 + mix + msg[i]);

        A = newA; B = newB; C = newC; D = newD; E = newE;
    }

    digest[0] = A;
    digest[1] = B;
    digest[2] = C;
    digest[3] = D;
    digest[4] = E;
    return digest;
}
