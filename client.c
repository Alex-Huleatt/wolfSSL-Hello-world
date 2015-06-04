#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/test.h>
#include <errno.h>

#define SERV_PORT 11111


int main()
{
    int sockfd; 
    WOLFSSL_CTX* ctx;
    WOLFSSL* ssl;
    WOLFSSL_METHOD* method;
    struct  sockaddr_in servAddr;           /* struct for server address */
    const char message[] = "Hello, World!";

    sockfd = socket(AF_INET, SOCK_STREAM, 0); /* create socket file description */
    memset(&servAddr, 0, sizeof(servAddr)); /* clears memory block for use */  
    servAddr.sin_family = AF_INET;          /* sets address family to internet*/
    servAddr.sin_port = htons(SERV_PORT);   /* sets port to defined port */
    connect(sockfd, (struct sockaddr *) &servAddr, sizeof(servAddr)); /* connect to socket */

    wolfSSL_Init(); /* initialize wolfssl library */

    method = wolfTLSv1_2_client_method(); /* use TLS v1.2 */

    /* make new ssl context */
    if ( (ctx = wolfSSL_CTX_new(method)) == NULL) {
        err_sys("wolfSSL_CTX_new error");
    }

    if ( (ssl = wolfSSL_new(ctx)) == NULL) {
        err_sys("wolfSSL_new error");
    }

    /* Add cert to ctx */
    if (wolfSSL_CTX_load_verify_locations(ctx, "certs/ca-cert.pem", 0) != 
                SSL_SUCCESS) {
        err_sys("Error loading certs/ca-cert.pem");
    }

    wolfSSL_set_fd(ssl, sockfd); /* Connect wolfssl to the socket */
    wolfSSL_connect(ssl); /* connect to server */
    wolfSSL_write(ssl, message, strlen(message)); /* send message to server */

    /* frees all data before client termination */
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
    wolfSSL_Cleanup();
}