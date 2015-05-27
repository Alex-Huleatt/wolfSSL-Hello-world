#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <wolfssl/ssl.h>

#define DEFAULT_PORT 11111

void AcceptAndRead(WOLFSSL_CTX* ctx, socklen_t sockfd, struct sockaddr_in clientAddr)
{
    WOLFSSL* ssl;
    char buff[256];
    socklen_t size = sizeof(clientAddr);
    
    socklen_t connd = accept(sockfd, (struct sockaddr *)&clientAddr, &size); /* Wait until a client connects */
    ssl = wolfSSL_new(ctx);
    
    wolfSSL_set_fd(ssl, connd); /* direct our ssl to our clients connection */
    wolfSSL_read(ssl, buff, sizeof(buff)-1); /* Read the client data into our buff array */
    printf("%s\n", buff); /* Print any data the client sends to the console */
    wolfSSL_free(ssl);    /* Free the WOLFSSL object */
    close(connd);         /* close the connected socket */
}

int main() {
    WOLFSSL_CTX* ctx;
    socklen_t sockfd = socket(AF_INET, SOCK_STREAM, 0);
    WOLFSSL_METHOD* method;
    struct sockaddr_in serverAddr, clientAddr;

    wolfSSL_Init();

    method = wolfTLSv1_2_server_method(); /* set wolfssl to use TLS v 1.2 */

    ctx = wolfSSL_CTX_new(method); /* create and initialize WOLFSSL_CTX structure */

    /* Load server cert and private key */
    wolfSSL_CTX_use_certificate_file(ctx, "certs/server-cert.pem", SSL_FILETYPE_PEM);
    wolfSSL_CTX_use_PrivateKey_file(ctx, "certs/server-key.pem", SSL_FILETYPE_PEM);

    /* Fill the server's address family */
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(DEFAULT_PORT);

    /* Attach the server socket to our port */
    bind(sockfd, (struct sockaddr *)&serverAddr, sizeof(serverAddr));

    if (listen(sockfd, 1) == 0) AcceptAndRead(ctx, sockfd, clientAddr);

    wolfSSL_CTX_free(ctx);   /* Free WOLFSSL_CTX */
    wolfSSL_Cleanup();       /* Free wolfSSL */
    return 0;
}