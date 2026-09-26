#pragma once

#include <stdio.h>
#include <string.h>
#include <time.h>
#include "hash.h"

#define STRUCT_SIZE sizeof(struct User) // Block size in bytes


typedef struct User {
	char Username[20];
	time_t loginTime;
	struct tm localLoginTime;
	unsigned char* prevHash;
	struct User* next;
	struct Digest hash;
};



struct User* add(struct User*, char*);
void printUser(struct User*);
void printLog(struct User*);
void generateDigest(struct Digest* digest, struct User* User);
void verify(struct User*);
