#include <dlfcn.h>
#include <stdio.h>

int
main(int argc, char *argv[])
{
	if (!(dlopen(".libs/pam_ssh.so", RTLD_NOW))) {
		fprintf(stderr, "%s\n", dlerror());
		return 1;
	}
	return 0;
}
