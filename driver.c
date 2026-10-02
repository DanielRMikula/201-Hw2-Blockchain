#include <stdio.h>
#include <string.h>
#include "user.h"
#include <stdlib.h>

int main(void) {
	struct User* head= NULL;
	head = add(head, "rob");
	head = add(head, "hanif");
	head = add(head, "gahyun");
	head = add(head, "matt");
	head = add(head, "sumita");
	head = add(head, "james");
	verify(head);
	while (head != NULL) {
		struct User* next = head->next;
		free(head);
		head = next;
	}
	return 0;
}
