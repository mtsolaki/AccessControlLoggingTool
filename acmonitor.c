#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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

} entry;

typedef struct mal_user {
	int uid;  /* user id (positive integer) */
	int tries; /* how many times this user had tryied to access files with no permission */

} mal_user;

typedef struct file_mod {

	int uid;
	unsigned char fingerprint[16]; /* file fingerprint */
	
} file_mod;

typedef struct user_mod {
	int uid;
	int mod_count;
	unsigned char fingerprint[16]; /* file fingerprint */
} user_mod;

void
usage(void)
{
	printf(
	       "\n"
	       "usage:\n"
	       "\t./monitor \n"
		   "Options:\n"
		   "-m, Prints malicious users\n"
		   "-i <filename>, Prints table of users that modified "
		   "the file <filename> and the number of modifications\n"
		   "-h, Help message\n\n"
		   );

	exit(1);
}
void
print_hex(unsigned char *data, size_t len)
{
	size_t i;

	if (!data)
		printf("NULL data\n");
	else {
		for (i = 0; i < len; i++) {
			if (!(i % 16) && (i != 0))
				printf("%02X ", data[i]);
			printf("%02X ", data[i]);
		}
		printf("\n");
	}
}

void list_unauthorized_accesses(FILE *log)
{
	/* Take the logs from the file */

	fseek(log, 0, SEEK_END);
	int length = ftell(log);
	rewind(log);	

	int size = length/sizeof(entry);
	entry en_array[size];

	fread(en_array, size, sizeof(entry), log);

	/*Find and store all users that is malicious */
	mal_user *mal_us = (mal_user *)malloc(sizeof(mal_user));
	int i = 0, j = 0;
	int mal_count = 0;
	int exists;
	for (i = 0; i < size; i++) /* diatrexw ola ta logs */
	{	
		exists = 0;
		if ( en_array[i].action_denied == 1 && mal_count == 0) /* first user thar tried to access */
		{	
			mal_us[0].uid = en_array[i].uid;
			mal_us[0].tries = 1;
			mal_count++;
		}
		if ( en_array[i].action_denied == 1 && mal_count > 0)
		{
			for (j = 0; j < mal_count; j++)
			{
				if (en_array[i].uid == mal_us[j].uid)
				{
					mal_us[j].tries++;
					exists = 1;
				}
			}
			if (exists == 0)
			{
				mal_us = (mal_user *)realloc(mal_us, sizeof(mal_user)*(mal_count+1));
				mal_us[mal_count].uid = en_array[i].uid;
				mal_us[mal_count].tries = 1;
				mal_count++;
			}
		}
	
	} 
	for (i = 0; i < mal_count; i++)
	{
		if (mal_us[i].tries > 6)
		{
			printf ("Malicious UID: %d Tries to access files with no permition: %d\n", mal_us[i].uid, mal_us[i].tries );
		}
	} 

	return;

}
int fingerprint_comp(unsigned char* fing1,unsigned char *fing2)
{
	int i = 0;
	for ( i = 0; i < 16; i++)
	{
		if (fing1[i] != fing2[i])
		{
			return 0;
		}
	}

	return 1;
}

void
list_file_modifications(FILE *log, char *file_to_scan)
{
	/* Take the logs from the file */

	fseek(log, 0, SEEK_END);
	int length = ftell(log);
	rewind(log);	

	int size = length/sizeof(entry);
	entry en_array[size];

	fread(en_array, size, sizeof(entry), log);

	char path[MAX_PATH_NAME];
	char * r = realpath(file_to_scan, path);
	if (r == NULL){
		printf("The file you inserted didn't found");
		exit(0);
	}

	file_mod * fm =(file_mod *)malloc(sizeof(file_mod));
	int found;
	int logs = 0;
	int i = 0, j = 0;

	for ( i = 0; i < size; i++)
	{	
		found = strcmp(path, en_array[i].file);
		if (found == 0)
		{
			fm = (file_mod *)realloc(fm, sizeof(file_mod)*(logs+1));
			fm[logs].uid = en_array[i].uid;
			strcpy(fm[logs].fingerprint, en_array[i].fingerprint);
			logs++;
		}
	}
	user_mod *um = (user_mod *)malloc(sizeof(user_mod));
	int exists = 0;
	int um_count = 0;
	int modified = 0;
	int fing_c;
	for ( i = 0; i < logs; i++)
	{	
		exists = 0;
		if (i == 0 && um_count == 0)
		{
			um[um_count].uid = fm[i].uid;
			um[um_count].mod_count = 1;
			strcpy(um[um_count].fingerprint, fm[i].fingerprint);
			um_count++;
		}
		if (um_count > 0)
		{
			for (j = 0; j < um_count; j++)
			{
				if (um[j].uid == fm[i].uid)
				{
					fing_c = fingerprint_comp(um[j].fingerprint, fm[i].fingerprint);
					exists = 1;
					if (fing_c == 0)
					{
						strcpy(um[j].fingerprint, fm[i].fingerprint);
						um[j].mod_count += 1;
					}
				}
			}
			if (exists == 0)
			{
				um = (user_mod *)realloc(um, sizeof(user_mod)*(um_count+1));
				um[um_count].uid = fm[i].uid;
				um[um_count].mod_count = 1;
				strcpy(um[um_count].fingerprint, fm[i].fingerprint);
				um_count++;
			}
			
		}

	}
	printf("  UID  | Modifications  \n");
	for (i = 0; i < um_count; i++)
	{
		printf(" %d  | %d \n", um[i].uid, um[i].mod_count);

	}
	/* add your code here */
	/* ... */
	/* ... */
	/* ... */
	/* ... */

	return;

}


int 
main(int argc, char *argv[])
{

	int ch;
	FILE *log;

	if (argc < 2)
		usage();

	log = fopen("./file_logging.log", "r");
	if (log == NULL) {
		printf("Error opening log file \"%s\"\n", "./log");
		return 1;
	}


	while ((ch = getopt(argc, argv, "hi:m")) != -1) {
		switch (ch) {		
		case 'i':
			list_file_modifications(log, optarg);
			break;
		case 'm':
			list_unauthorized_accesses(log);
			break;
		default:
			usage();
		}

	}

	/* add your code here */
	/* ... */
	/* ... */
	/* ... */
	/* ... */


	fclose(log);
	argc -= optind;
	argv += optind;	
	
	return 0;
}
