#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/stat.h>


int main() 
{
	int i;
	size_t bytes;
	FILE *file;
	char filenames[11][7] = {"file_0", "file_1", 
			"file_2", "file_3", "file_4",
			"file_5", "file_6", "file_7", 		
			"file_8", "file_9", "file10"};

	char mode[]="0000";
	char access[]="0777";
    char buf[100];
	int m;

	/* example source code */

	for (i = 0; i < 11; i++) {
		
		file = fopen(filenames[i], "w+");
		if (file == NULL) 
			perror("fopen");
		else {
			bytes = fwrite(filenames[i], strlen(filenames[i]), 1, file);
			fclose(file);
		}

	}

	for (i = 0; i < 11; i++) { /* modifies the file */

		realpath(filenames[i], buf);
		file = fopen(filenames[i], "w+");
		if (file == NULL) 
			perror("fopen");
		else {
			bytes = fwrite(buf, strlen(buf), 1, file);
			fclose(file);
		}

	}
	for(i = 0; i < 11; i++) /*makes permition denied */
	{	
		
		m = strtol(mode, 0, 8);
		realpath(filenames[i], buf);
		if(chmod(buf, m) < 0)
		{
			perror("chmod");
		}
		file = fopen(filenames[i], "w+");
		if (file == NULL) 
			perror("fopen");
		else {
			bytes = fwrite(buf, strlen(buf), 1, file);
			fclose(file);
		}
		m = strtol(access, 0, 8);
		realpath(filenames[i], buf);
		if(chmod(buf, m) < 0)
		{
			perror("chmod");
		}
	}



}
