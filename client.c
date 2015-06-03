#include <wolfssl/ssl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>

#define SERV_PORT 11111

const char* cert = "certs/ca-cert.pem";

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
    ctx = wolfSSL_CTX_new(method); /* make new ssl context */
    ssl = wolfSSL_new(ctx);

    wolfSSL_CTX_load_verify_locations(ctx, cert, 0); /* Add cert to ctx */

    wolfSSL_set_fd(ssl, sockfd); /* Connect wolfssl to the socket */
    wolfSSL_connect(ssl); /* connect to server */
    wolfSSL_write(ssl, message, strlen(message)); /* send message to server */

    /* frees all data before client termination */
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
    wolfSSL_Cleanup();
}