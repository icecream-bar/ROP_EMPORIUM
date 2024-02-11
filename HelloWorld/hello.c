#include <stdio.h>
#include <string.h>

int pPRINT(char *arg){
	char name[16];
	strcpy(name, arg);
	printf("Hello %s\n", name);
	return 0;
}

int main(int argc, char *argv[])
{
	if(argc>1){
		pPRINT(argv[1]);
		return 0;
	}
	else{
		printf("Hello World\n");
		return 0;
	}
}

