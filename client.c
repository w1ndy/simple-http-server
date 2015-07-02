#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#include "http.h"
#include "log.h"

int main(int argc, char *argv[])
{
    int sockfd, portno, n;
    struct sockaddr_in serv_addr;
    struct hostent *server;

    log_init("client.log", 1);

    char buffer[2049];
    int buflen;
    char url[256], host[256], res[256];
    printf("URL to access: ");
    gets(url);
    if(strncmp(url, "http://", 7)) {
        printf("error: url should started with http://\n");
        return -1;
    }

    int i, len = strlen(url), hostlen = 0;
    for(i = 7; i < len; i++, hostlen++) {
        if(url[i] == ':') {
            strncpy(host, url + 7, hostlen);
            portno = atoi(url + i + 1);
            while(i < len && url[i] != '/') i++;
            if(i >= len) strcpy(res, "/");
            else strcpy(res, url + i);
            break;
        } else if(url[i] == '/') {
            strncpy(host, url + 7, hostlen);
            portno = 80;
            strcpy(res, url + i);
            break;
        }
    }
    if(i >= len) {
        printf("error: malformed url");
        return 0;
    }

    printf("connecting to host %s at port %d with url %s\n", host, portno, res);
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
        perror("error while opening socket: ");
    server = gethostbyname(host);
    if (server == NULL) {
        perror("host not found: ");
        return 0;
    }
    bzero((char *) &serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    bcopy((char *)server->h_addr,
         (char *)&serv_addr.sin_addr.s_addr,
         server->h_length);
    serv_addr.sin_port = htons(portno);
    if (connect(sockfd,(struct sockaddr *) &serv_addr,sizeof(serv_addr)) < 0) {
        perror("error while connecting: ");
        return 0;
    }

    http_request_t req;
    http_response_t resp;
    http_request_init(&req);
    http_response_init(&resp);
    req.type = HTTP_GET;
    strcpy(req.url, res);
    req.version = HTTP_VERSION_1_1;
    sprintf(host, "%s:%d", host, portno);
    dict_put(req.fields, "Host", host);
    if(0 > http_assemble_request(&req, sockfd)) {
        perror("error while writing: ");
        return 0;
    }

    buflen = 0;
    do {
        n = read(sockfd, buffer + buflen, 2048 - buflen);
        if(n > 0)
            buflen += n;
    } while(n > 0 && buflen < 2048);

    puts("===raw resp===");
    for(i = 0; i < buflen; i++) {
        putchar(buffer[i]);
    }
    puts("\n===end===\n");

    if(http_parse_response(&resp, buffer, buflen)) {
        printf("error while parsing response\n");
        return 0;
    }
    printf("%s\n", resp.document);
    http_request_free(&req);
    http_response_free(&resp);
    close(sockfd);
    log_close();
    return 0;
}
