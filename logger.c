#define _GNU_SOURCE

#include <time.h>
#include <stdio.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <openssl/md5.h>
#include <errno.h>

#define MAX_PATH_NAME 100


typedef struct entry {

	int uid; /* user id (positive integer) */
	int access_type; /* access type values [0-2] */
	int action_denied; /* is action denied values [0-1] */

	struct date *tm; /* file access date and time */

	char file[MAX_PATH_NAME]; /* filename (string) */
	unsigned char fingerprint[16]; /* file fingerprint */

	/* add here other fields if necessary */
	/* ... */
	/* ... */

} log;

FILE *fopen(const char *path, const char *mode) 
{

	FILE *original_fopen_ret;
	FILE *(*original_fopen)(const char*, const char*);

	/* call the original fopen function */
	original_fopen = dlsym(RTLD_NEXT, "fopen");
	original_fopen_ret = (*original_fopen)(path, mode);

	/* call the original fwrite function */
	size_t (*original_fwrite)(const void*, size_t, size_t, FILE*);
	original_fwrite = dlsym(RTLD_NEXT, "fwrite");

	log *logvar = (log *)malloc(sizeof(log));

	/* check if the file was created or not */
	if (access(path, F_OK) == -1)
	{
		logvar->access_type = 0;
	} else 
	{
		logvar->access_type = 1;
	}

	/* get the path fot the file */
	strcpy(logvar->file,realpath(path, NULL));

	/* get user ID */
	logvar->uid = getuid();
	
	/* Check if the user have no privileges */
	if(original_fopen_ret == NULL && errno == 13)
	{
		logvar->action_denied = 1;
	}else
	{
		logvar->action_denied = 0;
	}

	/*take current date and time */
	time_t t = time(NULL);
	logvar->tm = localtime(&t);

	/* make fingerprint */
	if(original_fopen_ret != NULL)
	{
		fseek(original_fopen_ret, 0, SEEK_END);
		int length = ftell(original_fopen_ret);
		rewind(original_fopen_ret);	

		unsigned char *contents = (unsigned char *)malloc(length*sizeof(char));
		fread(contents, 1, length, original_fopen_ret);

		MD5(contents, length, logvar->fingerprint);
		free(contents);
	}else
	{
		MD5(NULL, 0, logvar->fingerprint);
	}

	/* store The struct into the file_logging.log */
	FILE *fp;
	fp = (*original_fopen)("file_logging.log", "ab");
	//perror("fopen");
	(*original_fwrite)(logvar, sizeof(log), 1, fp);
	fclose(fp);

	return original_fopen_ret;
}


size_t 
fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream) 
{

	size_t original_fwrite_ret;
	size_t (*original_fwrite)(const void*, size_t, size_t, FILE*);

	/* call the original fwrite function */
	original_fwrite = dlsym(RTLD_NEXT, "fwrite");
	original_fwrite_ret = (*original_fwrite)(ptr, size, nmemb, stream);

	/* call the original fopen function */
	FILE *(*original_fopen)(const char*, const char*);
	original_fopen = dlsym(RTLD_NEXT, "fopen");

	log *logvar = (log *)malloc(sizeof(log));

	/* Find path and store it */
	int fno = fileno(stream);
	char buff[MAX_PATH_NAME];
	sprintf(buff, "/proc/self/fd/%d", fno);
	readlink(buff, buff, MAX_PATH_NAME);
	//perror("readLink");
	strcpy(logvar->file, buff);

	/* get user ID */
	logvar->uid = getuid();

	/* Check if the user have no privileges */
	if(original_fwrite_ret < nmemb && errno == 13)
	{
		logvar->action_denied = 1;
	}else
	{
		logvar->action_denied = 0;
	}

	/*take current date and time */
	time_t t = time(NULL);
	logvar->tm = localtime(&t);

	/* Set access type to write */
	logvar->access_type = 2;

	/* make fingerprint */
	if(stream != NULL)
	{
		fseek(stream, 0, SEEK_END);
		int length = ftell(stream);
		rewind(stream);	

		unsigned char *contents = (unsigned char *)malloc(length*sizeof(char));
		fread(contents, 1, length, stream);

		MD5(contents, length, logvar->fingerprint);
		free(contents);
	}else
	{
		MD5(NULL, 0, logvar->fingerprint);
	}

	/* store The struct into the file_logging.log */
	FILE *fp;
	fp = (*original_fopen)("file_logging.log", "ab");
	//perror("fopen");
	(*original_fwrite)(logvar, sizeof(log), 1, fp);
	fclose(fp);

	/* add your code here */
	/* ... */
	/* ... */
	/* ... */
	/* ... */


	return original_fwrite_ret;
}

