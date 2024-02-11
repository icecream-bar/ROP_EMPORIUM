#include <stdlib.h>
#include <stdio.h>
#include <string.h>

int main (void){
	int* ptr;
	ptr = (int*) malloc(20 * sizeof(int));
	if(ptr){
		printf("Memory successfully allocated!\n");
		memset(ptr, 0x41, 20 * sizeof(ptr));

	}
	else{
		printf("Mamory allocation failed!\n");
	}
	exit(0);

}
