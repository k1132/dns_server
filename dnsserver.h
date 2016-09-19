#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/ipc.h>
#include <sys/shm.h>

// **************************************** //


/**
	DNS SERVER function headers
**/

// DNS Server communication functions
void sendReply(unsigned short id, unsigned char* query, int ip_addr, int sockfd, struct sockaddr_in dest);
u_char* convertRFC2Name(unsigned char* reader,unsigned char* buffer,int* count);
void convertName2RFC(unsigned char* dns,unsigned char* host);

// DNS Server functions
int create_managers();

// Configuration Manager Functions
void config_manager();

// Statistics Manager Functions
void stats_manager();

//Map DNS file
void map_localdns_file();
void clear_mmap_file();

// Shared Memory
void create_shared_memory();
void free_shared_memory();

// Signal handling functions
void handle_signals();
void handle_exit_c();
void handle_exit_z();
void handle_confs();

// Pipes
int* create_pipe();



/**
	Config manager Function headers
**/

void config_manager();
void read_from_file();
