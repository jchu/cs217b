#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>


int main()
{
    const char host[] = "localhost";

    enum { READ = 0, WRITE = 1 };

    int c, fd[2];
    FILE *childstdout;
    FILE *childstdin;

    if (pipe(fd) == -1 || (childstdout = fdopen(fd[READ], "r")) == NULL) {
        perror("pipe() or fdopen() failed");
        return 1;
    }

    switch (fork()) {

      case 0:  // Child
        close(fd[READ]);
        if (dup2(fd[WRITE], STDOUT_FILENO) != -1)
            execlp("ssh", "ssh", host, NULL);

      case -1: // Error
        perror("fork() failed");
        return 1;
    }

    close(fd[WRITE]);
    // Write remote command output to stdout;
    while ((c = getc(childstdout)) != EOF)	{
	printf("%c",c);
	}

    if (ferror(childstdout)) {
        perror("I/O error");
        return 1;
    }
}
