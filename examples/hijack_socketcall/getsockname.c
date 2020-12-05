#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#define DEBUG 2
#define SUCCESS 0
#define FAILURE 1

// gcc -m32 getsockname.c -g -o getsockname

#if defined(DEBUG)
#include <stdio.h>
#define DBG_PRINT(level, ...) { \
    if (level <= DEBUG) {       \
        fprintf(stderr, __FILE__"(%d) (%d)", level, __LINE__); \
        fprintf(stderr, __VA_ARGS__); \
        fflush(stderr); \
    } \
}
#else
#define DBG_PRINT(level, ...) { }
#endif

int main(int argc, char * argv[]) {
    int sock_fd = -1;
    struct sockaddr_in server_addr, client_addr;

    if (argc < 3) {
        DBG_PRINT(1, "Usage: %s [ip] [port]\n", argv[0]);
        exit(FAILURE);
    }

    char * server_ip = argv[1];
    int server_port = atoi(argv[2]);

    sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_fd == -1) { 
        DBG_PRINT(2, "socket creation failed...\n");
        exit(FAILURE);
    } 

    bzero(&server_addr, sizeof(server_addr)); 
  
    server_addr.sin_family = AF_INET; 
    server_addr.sin_addr.s_addr = inet_addr(server_ip);
    server_addr.sin_port = htons(server_port); 
  
    if (connect(sock_fd, (struct sockaddr *) &server_addr, sizeof(server_addr)) != 0) { 
        DBG_PRINT(2, "connection with the server failed...\n"); 
        exit(FAILURE); 
    } 

    int len = sizeof(client_addr);
    int rv = SUCCESS;
    char client_ip[16] = { 0 };
    int client_port = -1;
    bzero(&client_addr, sizeof(client_addr));

    // get src ip of socket connection
    rv = getsockname(sock_fd, (struct sockaddr *) &client_addr, &len);
    if (rv != SUCCESS) {
        DBG_PRINT(1, "getsockname returned: %d\n", rv);
        exit(FAILURE);
    }

    inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));
    client_port = ntohs(client_addr.sin_port);

    DBG_PRINT(1, "client ip address: %s\n", client_ip);
    DBG_PRINT(1, "client port : %u\n", client_port);

    return rv;
}
