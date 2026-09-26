#pragma once
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

struct Digest {
	unsigned char hash0, hash1, hash2, hash3, hash4;
};

#define DIGEST_SIZE 5 

//unsigned char* toString(struct Block* blk);
unsigned char* SSHA(const unsigned char* str, size_t size);
int digest_equal(struct Digest digest1, struct Digest digest2);
void printDigest(struct Digest digest);