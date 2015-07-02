#ifndef __HTTP_H__
#define __HTTP_H__

#define HTTP_MAX_REQUEST_URL    256
#define HTTP_MAX_FIELD_LENGTH   128
#define HTTP_VERSION_LENGTH     16

#define HTTP_VERSION_1_1_STRING "HTTP/1.1"
#define HTTP_VERSION_1_0_STRING "HTTP/1.0"

#define HTDOCS  "/home/w1ndy/htdocs"

#include "dictionary.h"

typedef enum {
    HTTP_INVALID = 0,
    HTTP_GET,
    HTTP_POST
} http_request_type_t;

typedef enum {
    HTTP_VERSION_UNKNOWN = 0x0000,

    HTTP_VERSION_1_0 = 0x0100,
    HTTP_VERSION_1_1 = 0x0101
} http_version_t;

typedef struct {
    http_request_type_t type;
    http_version_t      version;
    char    url[HTTP_MAX_REQUEST_URL + 1];
    dict_t *fields;
} http_request_t;

typedef struct {
    http_version_t  version;
    int             status_code;
    dict_t *        fields;

    char    fname[HTTP_MAX_REQUEST_URL + 30];
    int     document_length;
    char   *document;
} http_response_t;

int http_url_decode(char *url);
const char *http_code_to_string(int code);
http_request_type_t http_translate_request_type(const char *s);
const char *http_encode_request_type(http_request_type_t type);

void http_request_init(http_request_t *header);
void http_request_free(http_request_t *header);
void http_response_init(http_response_t *header);
void http_response_free(http_response_t *header);

int  http_assemble_request(http_request_t *header, int fd);
int  http_parse_request(http_request_t *header,
                        char *buf, int buflen);
int  http_assemble_response(http_response_t *header, int fd);
int  http_parse_response(http_response_t *header,
                         char *buf, int buflen);

void http_server_serve_request(int fd, char *buf, int buflen);

void http_response_400(http_response_t *header);
void http_response_403(http_response_t *header);
void http_response_404(http_response_t *header);
void http_response_200(http_response_t *header);

#endif // __HTTP_H__
