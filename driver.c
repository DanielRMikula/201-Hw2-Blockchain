#include <stdio.h>
#include <string.h>
#include "user.h"


int main(void) {
	struct user * head=NULL;
	head = add(head, "rob");
	head = add(head, "hanif");
	head = add(head, "gahyun");
	head = add(head, "matt");
	head = add(head, "sumita");
	head = add(head, "james");
	verify(head);
}