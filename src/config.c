#include "../include/config.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <uv.h>

#include "../include/log.h"

char *REMOTE_HOST = "8.8.8.8";
int LOG_MASK = 15;
int CLIENT_PORT = 0;
char *HOSTS_PATH = "../dnsrelay.txt";
char *LOG_PATH = NULL;

/**
 * @brief Parse command line arguments
 * @param argc Number of arguments
 * @param argv Array of argument strings
 */
void init_config(int argc, char *const *argv) {
	argc--;
	argv++;

	fprintf(stderr, " _____ _     ____  _   _ ____    ____      _\n");
	fprintf(stderr, "|_   _| |   |  _ \\| \\ | / ___|  |  _ \\ ___| | __ _ _   _\n");
	fprintf(stderr, "  | | | |   | | | |  \\| \\___ \\  | |_) / _ \\ |/ _` | | | |\n");
	fprintf(stderr, "  | | | |___| |_| | |\\  |___) | |  _ <  __/ | (_| | |_| |\n");
	fprintf(stderr, "  |_| |_____|____/|_| \\_|____/  |_| \\_\\___|_|\\__,_|\\__, |\n");
	fprintf(stderr, "                                                   |___/\n\n");

	fflush(stderr);

	if (argc == 1 && strcmp(*argv, "-h") == 0) {
		printf("Usage:\n");
		printf("    [-a] Use the specified name server\n");
		printf("    [-d] Debug level mask, a 4-bit binary number, DEBUG、INFO、ERROR、FATAL in order\n");
		printf("    [-f] Use the specified DNS hosts file\n");
		printf("    [-l] Log information storage location\n");
		printf("    [-p] Custom listening ports\n");
		printf("    [-h] Helpful Information\n\n");
		printf("Example:\n");
		printf("    –d 1111 -a 192.168.0.1 -f c:\\dns-table.txt\n");
		printf("        Output all debugging information\n");
		printf("        Use the specified name server 192.168.0.1\n");
		printf("        Use the specified configuration file c:\\\\dns-table.txt\n");
		printf("    -d 1101 -l /Users/Code -p 53\n");
		printf("        Output DEBUG、INFO、and FATAL information\n");
		printf("        Output debugging information to /Users/Code as a file\n");
		fflush(stdout);
		exit(0);
	}

	int i = 0;
	while (i < argc) {
		char *field = argv[i];
		if (field[0] != '-')
			log_fatal("Command line parameter is wrong, parameter flags must start with -.")
		field++;
		if (i + 1 == argc)
			log_fatal("Command line parameter is wrong, missing parameter values")

		switch (*field) {
			case 'a': {
				char *dest = (char*)malloc(5 * sizeof(char));
				if (!dest)
					log_fatal("Failure to allocate memory")
				if (uv_inet_pton(AF_INET, argv[i + 1], dest))
					log_fatal("Command line parameter is wrong, entered illegitimate IP address")
				free(dest);
				REMOTE_HOST = argv[i + 1];
				i += 2;
				break;
			}
			case 'd': {
				int mask = (int)strtol(argv[i + 1], NULL, 2);
				if (mask < 0 || mask > 15)
					log_fatal("Command line parameter is wrong, mask must be an integer from 0-15")
				LOG_MASK = mask;
				i += 2;
				break;
			}
			case 'f': {
				HOSTS_PATH = argv[i + 1];
				i += 2;
				break;
			}
			case 'l': {
				LOG_PATH = argv[i + 1];
				i += 2;
				break;
			}
			case 'p': {
				int port = (int)strtol(argv[i + 1], NULL, 10);
				if (port < 1024 || port > 65535)
					log_fatal("Command line parameter is wrong, port must be an integer of 1024-65535")
				CLIENT_PORT = port;
				i += 2;
				break;
			}
			default:
				log_fatal("Command line parameter is wrong, Illegal parameter flags")
		}
	}
}