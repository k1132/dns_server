#include "dnsserver.h"

// Path to the local DNS folder
#define LOCALDNSPATH "localdns.txt"

// Path to the local DNS folder
#define CONFSPATH "confs.txt"

// Max size for config struts vars
#define MAX 500


/**
	STRUTS
**/

//DNS header structure
struct DNS_HEADER
{
    unsigned short id; // identification number
 
    unsigned char rd :1; // recursion desired
    unsigned char tc :1; // truncated message
    unsigned char aa :1; // authoritive answer
    unsigned char opcode :4; // purpose of message
    unsigned char qr :1; // query/response flag
 
    unsigned char rcode :4; // response code
    unsigned char cd :1; // checking disabled
    unsigned char ad :1; // authenticated data
    unsigned char z :1; // its z! reserved
    unsigned char ra :1; // recursion available
 
    unsigned short q_count; // number of question entries
    unsigned short ans_count; // number of answer entries
    unsigned short auth_count; // number of authority entries
    unsigned short add_count; // number of resource entries
};
 
//Constant sized fields of query structure
struct QUESTION
{
    unsigned short qtype;
    unsigned short qclass;
};
 
//Constant sized fields of the resource record structure
#pragma pack(push, 1)
struct R_DATA
{
    unsigned short type;
    unsigned short _class;
    unsigned int ttl;
    unsigned short data_len;
};
#pragma pack(pop)
 
//Pointers to resource record contents
struct RES_RECORD
{
    unsigned char *name;
    struct R_DATA *resource;
    unsigned char *rdata;
};
 
//Structure of a Query
struct QUERY
{
    unsigned char *name;
    struct QUESTION *ques;
};

typedef struct cnode * configs;
typedef struct cnode {
	int n_threads;
	char * domains;
	char * local_domain;
	char * named_pipe;
}confnode;

/**
	GLOBAL VARS
**/

// Memory mapped file
int fd;
struct stat mystat;
void* localdns_file;

// Proccesses ids
pid_t parent_pid, config_pid, stats_pid;

// Shared Memory
char* shm;
int shmid;

// Configurations struct
configs configurations;

// Statistics Pipe
int *stats_pipe;

int main( int argc , char *argv[])
{



	unsigned char buf[65536], *reader;
	int sockfd, stop;
	struct DNS_HEADER *dns = NULL;
	
	struct sockaddr_in servaddr, dest;
	socklen_t len;

	//Initialize the struct
	configurations = (configs) calloc(1, sizeof(confnode));

	//Initialize Variables of the Struct
	configurations -> n_threads = -1;
	configurations -> domains = (char *) calloc(1024, sizeof(char));
	configurations -> local_domain = (char *) calloc(64, sizeof(char));
	configurations -> named_pipe = (char *) calloc(64, sizeof(char));

	// Create managers
	if(!create_managers())
	{
		printf("\nCritical error creating managers!\n");
		exit(1);
	}

	// Start listening to signals
	handle_signals();

	// Map local DNS file
	map_localdns_file();

	// Create shared memory
	create_shared_memory();
	
	// Read configs from file
	read_from_file();

	// Get a new pipe for stats communication
	stats_pipe = create_pipe();

	// Check arguments
	if(argc <= 1) {
		printf("Usage: dnsserver <port>\n");
		exit(1);
	}
	
	// Get server UDP port number
	int port = atoi(argv[1]);
	
	if(port <= 0) {
		printf("Usage: dnsserver <port>\n");
		exit(1);
	}
	
	
	// ****************************************
	// Create socket & bind
	// ****************************************
	
	// Create UDP socket
    sockfd = socket(AF_INET , SOCK_DGRAM , IPPROTO_UDP); //UDP packet for DNS queries
 
	if (sockfd < 0) {
         printf("ERROR opening socket.\n");
		 exit(1);
	}

	// Prepare UDP to bind port
	bzero(&servaddr,sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr=htonl(INADDR_ANY);
	servaddr.sin_port=htons(port);
	
	// Bind application to UDP port
	int res = bind(sockfd,(struct sockaddr *)&servaddr,sizeof(servaddr));
	
	if(res < 0) {
         printf("Error binding to port %d.\n", servaddr.sin_port);
		 
		 if(servaddr.sin_port <= 1024) {
			 printf("To use ports below 1024 you may need additional permitions. Try to use a port higher than 1024.\n");
		 } else {
			 printf("Please make sure this UDP port is not being used.\n");
		 }
		 exit(1);
	}



	// ****************************************
	// Receive questions
	// ****************************************
	
	while(1) {
		// Receive questions
		len = sizeof(dest);
		printf("\n\n-- Wating for DNS message --\n\n");
		if(recvfrom(sockfd,(char*)buf , 65536 , 0 , (struct sockaddr*)&dest , &len) < 0) {
			printf("Error while waiting for DNS message. Exiting...\n");
			exit(1);
		}
		
		printf("DNS message received\n");

		// Process received message
		dns = (struct DNS_HEADER*) buf;
		//qname =(unsigned char*)&buf[sizeof(struct DNS_HEADER)];
		reader = &buf[sizeof(struct DNS_HEADER)];
	 
		printf("\nThe query %d contains: ", ntohs(dns->id));
		printf("\n %d Questions.",ntohs(dns->q_count));
		printf("\n %d Answers.",ntohs(dns->ans_count));
		printf("\n %d Authoritative Servers.",ntohs(dns->auth_count));
		printf("\n %d Additional records.\n\n",ntohs(dns->add_count));
		
		// We only need to process the questions
		// We only process DNS messages with one question
		// Get the query fields according to the RFC specification
		struct QUERY query;
		if(ntohs(dns->q_count) == 1) {
			// Get NAME
			query.name = convertRFC2Name(reader,buf,&stop);
			reader = reader + stop;
			
			// Get QUESTION structure
			query.ques = (struct QUESTION*)(reader);
			reader = reader + sizeof(struct QUESTION);
			
			// Check question type. We only need to process A records.
			if(ntohs(query.ques->qtype) == 1) {
				printf("A record request.\n\n");
			} else {
				printf("NOT A record request!! Ignoring DNS message!\n");
				continue;
			}
			
		} else {
			printf("\n\nDNS message must contain one question!! Ignoring DNS message!\n\n");
			continue;
		}
		
		// Received DNS message fulfills all requirements.
		
		
		// ****************************************
		// Print received DNS message QUERY
		// ****************************************
		printf(">> QUERY: %s\n", query.name);
		printf(">> Type (A): %d\n", ntohs(query.ques->qtype));
		printf(">> Class (IN): %d\n\n", ntohs(query.ques->qclass));
			
		// ****************************************
		// Example reply to the received QUERY
		// (Currently replying 10.0.0.2 to all QUERY names)
		// ****************************************
		sendReply(dns->id, query.name, inet_addr("10.0.0.2"), sockfd, dest);
	}
	
    return 0;
}

/**
	sendReply: this method sends a DNS query reply to the client
	* id: DNS message id (required in the reply)
	* query: the requested query name (required in the reply)
	* ip_addr: the DNS lookup reply (the actual value to reply to the request)
	* sockfd: the socket to use for the reply
	* dest: the UDP package structure with the information of the DNS query requestor (includes it's IP and port to send the reply)
**/
void sendReply(unsigned short id, unsigned char* query, int ip_addr, int sockfd, struct sockaddr_in dest) {
		unsigned char bufReply[65536], *rname;
		char *rip;
		struct R_DATA *rinfo = NULL;
		
		//Set the DNS structure to reply (according to the RFC)
		struct DNS_HEADER *rdns = NULL;
		rdns = (struct DNS_HEADER *)&bufReply;
		rdns->id = id;
		rdns->qr = 1;
		rdns->opcode = 0;
		rdns->aa = 1;
		rdns->tc = 0;
		rdns->rd = 0;
		rdns->ra = 0;
		rdns->z = 0;
		rdns->ad = 0;
		rdns->cd = 0;
		rdns->rcode = 0;
		rdns->q_count = 0;
		rdns->ans_count = htons(1);
		rdns->auth_count = 0;
		rdns->add_count = 0;
		
		// Add the QUERY name (the same as the query received)
		rname = (unsigned char*)&bufReply[sizeof(struct DNS_HEADER)];
		convertName2RFC(rname , query);
		
		// Add the reply structure (according to the RFC)
		rinfo = (struct R_DATA*)&bufReply[sizeof(struct DNS_HEADER) + (strlen((const char*)rname)+1)];
		rinfo->type = htons(1);
		rinfo->_class = htons(1);
		rinfo->ttl = htonl(3600);
		rinfo->data_len = htons(sizeof(ip_addr)); // Size of the reply IP address

		// Add the reply IP address for the query name 
		rip = (char *)&bufReply[sizeof(struct DNS_HEADER) + (strlen((const char*)rname)+1) + sizeof(struct R_DATA)];
		memcpy(rip, (struct in_addr *) &ip_addr, sizeof(ip_addr));
		
		// Send DNS reply
		printf("\nSending Answer... ");
		if( sendto(sockfd, (char*)bufReply, sizeof(struct DNS_HEADER) + (strlen((const char*)rname) + 1) + sizeof(struct R_DATA) + sizeof(ip_addr),0,(struct sockaddr*)&dest,sizeof(dest)) < 0) {
			printf("FAILED!!\n");
		} else {
			printf("SENT!!!\n");
		}
}

/**
	convertRFC2Name: converts DNS RFC name to name
**/
u_char* convertRFC2Name(unsigned char* reader,unsigned char* buffer,int* count) {
    unsigned char *name;
    unsigned int p=0,jumped=0,offset;
    int i , j;
 
    *count = 1;
    name = (unsigned char*)malloc(256);
 
    name[0]='\0';
 
    while(*reader!=0) {
        if(*reader>=192) {
            offset = (*reader)*256 + *(reader+1) - 49152;
            reader = buffer + offset - 1;
            jumped = 1;
        } else {
            name[p++]=*reader;
        }
 
        reader = reader+1;
 
        if(jumped==0) {
            *count = *count + 1;
        }
    }
 
    name[p]='\0';
    if(jumped==1) {
        *count = *count + 1;
    }
 
    for(i=0;i<(int)strlen((const char*)name);i++) {
        p=name[i];
        for(j=0;j<(int)p;j++) {
            name[i]=name[i+1];
            i=i+1;
        }
        name[i]='.';
    }
    name[i-1]='\0';
    return name;
}

/**
	convertName2RFC: converts name to DNS RFC name
**/
void convertName2RFC(unsigned char* dns,unsigned char* host) {
    int lock = 0 , i;
    strcat((char*)host,".");
     
    for(i = 0 ; i < strlen((char*)host) ; i++) {
        if(host[i]=='.') {
            *dns++ = i-lock;
            for(;lock<i;lock++) {
                *dns++=host[lock];
            }
            lock++;
        }
    }
    *dns++='\0';
}

/**
	handle_signals: Handle signals from CTRL + C/Z and maintenance mode
**/
void handle_signals()
{
	// Listen to keyboard signals for CTR + C
	signal(SIGINT, handle_exit_c);

	// Listen to keyboard signals for CTR + Z
	//signal(SIGTSTP, handle_exit_z);

	// Listen to keyboard signals for CTR + S
	// signal(SIGUSR1, handle_maintenance);
}

/**
	handle_exit_c: Handle CTRL + C Keys press
**/
void handle_exit_c()
{
	printf("\nCTRL + C: Shutting down!\n");
	clear_mmap_file();
	free_shared_memory();
	kill(config_pid, SIGKILL);
	kill(stats_pid, SIGKILL);
	exit(0);
}

/**
	handle_exit_z: Handle CTRL + Z Keys press
**/
void handle_exit_z()
{
	printf("\nCTRL + Z\n");
}


/**
	config_manager: Configuration Manager
**/
void config_manager()
{
	parent_pid = getppid();
	printf("\nConf Parent PID: %d\n", parent_pid);
	config_pid = getpid();
	printf("\nConfiguration Manager PID: %d\n", config_pid);
	printf("\nConfiguration Manager Created.\n");
	while(1) {

	}
}

/**
	stats_manager: Statistics Manager
**/
void stats_manager()
{
	parent_pid = getppid();
	printf("\nStats Parent PID: %d\n", parent_pid);
	stats_pid = getpid();
	printf("\nStatistics Manager PID: %d\n", stats_pid);
	printf("\nStatistics Manager Created.\n");
	while(1) {

	}
}

/**
	create_managers: Start Conf and Stats Manager
**/
int create_managers()
{
	config_pid = fork();
	if(config_pid == 0)
	{
		config_manager();
	} 
	else if(config_pid == -1)
	{
		perror("\nError creating Configuration Manager.\n");
		return -1;
	}
	else
	{
		stats_pid = fork();
		if(stats_pid == 0)
		{
			stats_manager();
		}
		else if(stats_pid == -1)
		{
			perror("\nError creating Statistics Manager.\n");
			return -1;
		}
		
		return 1;
	}
}

/**
	map_localdns_file: Open file descriptor and map local DNS file to memory
**/
void map_localdns_file()
{
	fd = open(LOCALDNSPATH, O_RDONLY);
	if(fd == -1)
	{
		perror("An error occurred while trying to create a file descriptor.");
		close(fd);
		exit(1);
	}

	if(fstat(fd, &mystat) == -1)
	{
		perror("An error occurred while trying to map the file in memory - fstat() function.");
		close(fd);
		exit(1);
	}

	localdns_file = mmap(0, mystat.st_size, PROT_READ, MAP_SHARED, fd, 0);

	if (localdns_file == MAP_FAILED)
	{
		perror("An error occurred while trying to map the file in memory - mmap() function.");
		close(fd);
		exit(1);
	}
}

/**
	clear_mmap_file: Close file descriptor and unmap memory
**/
void clear_mmap_file()
{
	// Don't forget to free the mmapped memory
    if (munmap(localdns_file, mystat.st_size) == -1)
    {
        close(fd);
        perror("Error un-mmapping the file");
        exit(EXIT_FAILURE);
    }

    // Un-mmaping doesn't close the file, so we still need to do that.
    close(fd);
}

/**
	read_from_file(): Read configurations from file to the configurations struct
**/
void read_from_file()
{
    char *line = (char *) calloc(1024, sizeof(char));
    
    int num_threads = -1, i = 1;
    char * domains, * local_domain, * named_pipe;

    FILE * file;
    file = fopen(CONFSPATH, "r");

    while(fgets(line, 100, file) != NULL) {
    	if(i == 1) {
    		strsep(&line, "=");
    		num_threads = atoi(strsep(&line, "\n"));
    		i++;
    	} else if(i == 2) {
    		strsep(&line, "=");
    		strsep(&line, " ");
    		domains = strsep(&line, "\n");
    		i++;
    	} else if(i == 3) {
    		strsep(&line, "=");
    		strsep(&line, " ");
    		local_domain = strsep(&line, "\n");
    		i++;
    	} else if(i == 4) {
    		strsep(&line, "=");
    		strsep(&line, " ");
    		named_pipe = strsep(&line, "\n");
    	}
    }
    
    fclose(file);

    printf("\n\nCONFIGURATION LOADED SUCCESSFULLY \n");
    configurations -> n_threads = num_threads;
    printf("Number of Threads: %d\n", configurations -> n_threads);
    configurations -> domains = domains;
    printf("Domains: %s\n", configurations -> domains);
    configurations -> local_domain = local_domain;
    printf("Local Domain: %s\n", configurations -> local_domain);
    configurations -> named_pipe = named_pipe;
    printf("Named Pipe: %s\n", configurations -> named_pipe);

}

/**
	create_shared_memory(): create shared memory
**/
void create_shared_memory()
{
	if ((shmid = shmget(IPC_PRIVATE, sizeof(confnode), IPC_CREAT|0700)) == -1 )
	{
		perror("SHMGET ERROR.\n" );
		exit(0);
	}

	if ((configurations = (configs) shmat(shmid, NULL, 0)) == (configs) -1 )
	{
		perror("SHMAT ERROR\n" );
		exit(0);
	}
}

/**
	free_shared_memory(): Remove shared memory
**/
void free_shared_memory()
{
	if (shmid >= 0)
	{
		if ( shmdt(configurations) == -1)
		{
			perror("Error relasing the shared memory.");
			exit(EXIT_FAILURE);
		}
		if (shmctl(shmid, IPC_RMID, NULL) == -1)
	    {
	        perror("Error releasing the shared memory.");
	        exit(EXIT_FAILURE);
	    }
	}
}

/**
	create_pipe(): Creates a new Pipe
**/
int* create_pipe()
{
	int fd[2];

	if (pipe(fd) == -1)
		perror("\nFailed to create the pipe");
	else
		printf("\nPipe Created.\n");

	return fd;
}