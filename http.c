#include "http.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "conn.h"
#include "log.h"

const char *default_400_document =
    "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">"
    "<html>"
    ""
    "<head>"
    "   <title>400 Bad Request</title>"
    "</head>"
    ""
    "<body>"
    "   <h1>Bad Request</h1>"
    "   <p>Your browser sent a request that this server could not understand.<p>"
    "</body>"
    ""
    "</html>";

const char *default_404_document =
    "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">"
    "<html>"
    ""
    "<head>"
    "   <title>404 Not Found</title>"
    "</head>"
    ""
    "<body>"
    "   <h1>Not Found</h1>"
    "   <p>Requested page could not be found on this server.<p>"
    "</body>"
    ""
    "</html>";

const char *default_403_document =
    "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">"
    "<html>"
    ""
    "<head>"
    "   <title>403 Forbidden</title>"
    "</head>"
    ""
    "<body>"
    "   <h1>Forbidden</h1>"
    "   <p>You have no permission accessing this location.<p>"
    "</body>"
    ""
    "</html>";

#define RESPONSE_FIELDS_SIZE 3
const char *response_fields[] = {"Server", "Content-Type", "Connection"};

#define REQUEST_FIELDS_SIZE 1
const char *request_fields[] = {"Host"};

void http_request_init(http_request_t *header)
{
    header->fields = dict_init();
}
void http_request_free(http_request_t *header)
{
    dict_free(header->fields);
}
void http_response_init(http_response_t *header)
{
    header->fields = dict_init();
}
void http_response_free(http_response_t *header)
{
    dict_free(header->fields);
}

char *trim(char *s)
{
    while(*s && (*s == ' ' || *s == '\n' || *s == '\t' || *s == '\r')) s++;
    if(*s == '\0') return s;
    int len = strlen(s), i;
    for(i = len - 1; i >= 0; i++) {
        if(s[i] == ' ' || s[i] == '\n' || s[i] == '\t' || s[i] == '\r')
            s[i] = 0;
        else
            break;
    }
    return s;
}

const char *http_code_to_string(int code)
{
    switch(code) {
        case 200: return "OK";
        case 400: return "Bad Request";
        case 403: return "Forbidden";
        case 404: return "Not Found";
    }
    return "Unknown";
}

http_request_type_t http_translate_request_type(const char *s)
{
    if(!strcmp(s, "GET"))
        return HTTP_GET;
    else if(!strcmp(s, "POST"))
        return HTTP_POST;
    return HTTP_INVALID;
}

const char *http_version_to_string(http_version_t ver)
{
    switch(ver) {
        case HTTP_VERSION_1_0:
            return HTTP_VERSION_1_0_STRING;
        case HTTP_VERSION_1_1:
            return HTTP_VERSION_1_1_STRING;
    }
    return "";
}

http_version_t http_translate_version(const char *s)
{
    if(strcmp(s, HTTP_VERSION_1_1_STRING) == 0)
        return HTTP_VERSION_1_1;
    if(strcmp(s, HTTP_VERSION_1_0_STRING) == 0)
        return HTTP_VERSION_1_0;
    return HTTP_VERSION_UNKNOWN;
}

int http_parse_request(http_request_t *header, char *buf, int buflen)
{
    int i, last, len, slen;
    header->type = HTTP_INVALID;
    buf[buflen + 1] = '\0';
    char *pch = strtok(buf, "\n");
    if(pch == NULL)
        return -1;
    len = strlen(pch);

    for(i = 0; i < len; i++) {
        if(pch[i] == ' ') {
            pch[i] = '\0';
            header->type = http_translate_request_type(trim(pch));
            break;
        }
    }
    if(i >= len) {
        ERROR("no http request type found in \"%s\"", pch);
        return -1;
    } else {
        DEBUG("http: request type %d", header->type);
    }

    for(last = ++i; i < len; i++) {
        if(pch[i] == ' ') {
            pch[i] = '\0';
            slen = strlen(pch + last);
            if(slen >= HTTP_MAX_REQUEST_URL) {
                ERROR("http request url exceeds maximum length (%d>=%d)",
                    slen, HTTP_MAX_REQUEST_URL);
                return -1;
            }
            strcpy(header->url, pch + last);
            break;
        }
    }
    if(i >= len) {
        ERROR("no http request url found in \"%s\"", pch + last);
        return -1;
    } else {
        http_url_decode(header->url);
        DEBUG("http: request url %s", header->url);
    }

    last = ++i;
    char *ver_string = trim(pch + last);
    if((header->version = http_translate_version(ver_string)) ==
        HTTP_VERSION_UNKNOWN) {
            ERROR("incompatible http version \"%s\"", ver_string);
            return -1;
    }

    pch = strtok(NULL, "\n");
    while(pch) {
        pch = trim(pch);
        len = strlen(pch);
        if(len == 0)
            return 0;
        for(i = 0; i < len; i++) {
            if(pch[i] == ':') {
                pch[i] = '\0';
                char *key = trim(pch);
                char *value = trim(pch + i + 1);
                dict_put_weak(header->fields, key, value);
                break;
            }
        }
        if(i >= len) {
            ERROR("invalid field specification \"%s\"", pch);
            return -1;
        }
        pch = strtok(NULL, "\n");
    }
    return 0;
}

int  http_parse_response(http_response_t *header, char *buf, int buflen)
{
    int i, len, slen;
    buf[buflen + 1] = '\0';
    char *pch = strtok(buf, "\n");
    len = strlen(pch);
    for(i = 0; i < len; i++) {
        if(pch[i] == ' ') {
            pch[i] = '\0';
            break;
        }
    }
    if(i >= len) {
        ERROR("no http version in \"%s\"", pch);
        return -1;
    }

    if((header->version = http_translate_version(pch)) ==
        HTTP_VERSION_UNKNOWN) {
            ERROR("incompatible http version \"%s\"", pch);
            return -1;
    }

    header->status_code = atoi(pch + i + 1);

    char *tpch;
    pch = strtok(NULL, "\n");
    while(pch) {
        tpch = trim(pch);
        len = strlen(tpch);
        if(len == 0) {
            header->document = pch + 2;
            return 0;
        }
        for(i = 0; i < len; i++) {
            if(tpch[i] == ':') {
                tpch[i] = '\0';
                break;
            }
        }
        char *key = trim(tpch);
        char *value = trim(tpch + i + 1);
        if(!strcmp(key, "Content-Length")) {
            header->document_length = atoi(value);
        } else {
            dict_put(header->fields, key, value);
        }
        pch = strtok(NULL, "\n");
    }

    ERROR("no document found");
    return -1;
}

const char *http_encode_request_type(http_request_type_t type)
{
    switch(type) {
        case HTTP_GET:
            return "GET";
        case HTTP_POST:
            return "POST";
    }
    return "GET";
}

int hex_to_byte(char p)
{
    if(p <= 'f' && p >= 'a') return p - 'a' + 10;
    else if(p <= 'F' && p >= 'A') return p - 'A' + 10;
    else if(p <= '9' && p >= '0') return p - '0';
    else return 0;
}

int hex_to_char(char *p)
{
    int ret = (hex_to_byte(*p) << 4) + hex_to_byte(*(p + 1));
    DEBUG("hex_to_char: %c%c to %d", *p, *(p + 1), ret);
    return ret;
}

const char *decode_table = " !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~";
int http_url_decode(char *url)
{
    int len = strlen(url), p = 0, i;
    char ret[HTTP_MAX_REQUEST_URL];
    for(i = 0; i < len; i++) {
        if(url[i] == '+') ret[p++] = ' ';
        else if(url[i] == '%' && i + 2 < len) {
            int hex = hex_to_char(url + i + 1);
            i += 2;
            if(hex < 32 || hex > 127) ret[p++] = (char)hex;
            else if(hex == 127) continue;
            else ret[p++] = decode_table[hex - 32];
        } else {
            ret[p++] = url[i];
        }
    }
    ret[p] = '\0';
    strcpy(url, ret);
}

int http_assemble_request(http_request_t *header, int fd)
{
    char buf[MAX_REQUEST_SIZE + 1];
    sprintf(buf, "%s %s %s\r\n", http_encode_request_type(header->type), header->url, http_version_to_string(header->version));

    int i;
    char field[HTTP_MAX_FIELD_LENGTH + 1];
    for(i = 0; i < REQUEST_FIELDS_SIZE; i++) {
        char *value = dict_get(header->fields, request_fields[i]);
        if(value) {
            sprintf(field, "%s: %s\r\n", request_fields[i], value);
            strcat(buf, field);
        }
    }
    strcat(buf, "\r\n");
    return write(fd, buf, strlen(buf));
}

void http_server_serve_request(int fd, char *buf, int buflen)
{
    DEBUG("serving request for %d", fd);
    http_request_t req;
    http_response_t resp;
    http_request_init(&req);
    http_response_init(&resp);

    if(http_parse_request(&req, buf, buflen)) {
        DEBUG("http: sending 400 response");
        http_response_400(&resp);
        goto completed;
    }

    int i, len = strlen(req.url);
    for(i = 0; i < len - 1; i++) {
        if(req.url[i] == '.' && req.url[i + 1] == '.') {
            DEBUG("http: sending 403 response");
            http_response_403(&resp);
            goto completed;
        }
    }

    strcpy(resp.fname, HTDOCS);
    strcat(resp.fname, req.url);
    if(!strcmp(req.url, "/"))
        strcat(resp.fname, "index.html");

    DEBUG("http: trying retrieving %s\n", resp.fname);
    FILE *fp = fopen(resp.fname, "r");
    if(fp == NULL) {
        DEBUG("http: sending 404 response");
        http_response_404(&resp);
    } else {
        DEBUG("http: sending %s", resp.fname);
        fseek(fp, 0, SEEK_END);
        resp.document_length = ftell(fp);
        fclose(fp);
        http_response_200(&resp);
    }

completed:
    http_assemble_response(&resp, fd);
    connmgr_kill_connection(fd);
    http_request_free(&req);
    http_response_free(&resp);
}

void http_response_400(http_response_t *header)
{
    header->version = HTTP_VERSION_1_1;
    header->status_code = 400;
    dict_put(header->fields, "Server", "httpsrv/1.0");
    dict_put(header->fields, "Content-Type", "text/html; charset=iso-8859-1");
    dict_put(header->fields, "Connection", "closed");
    header->document_length = strlen(default_400_document);
    header->document = (char *)default_400_document;
}

void http_response_403(http_response_t *header)
{
    header->version = HTTP_VERSION_1_1;
    header->status_code = 403;
    dict_put(header->fields, "Server", "httpsrv/1.0");
    dict_put(header->fields, "Content-Type", "text/html; charset=iso-8859-1");
    dict_put(header->fields, "Connection", "closed");
    header->document_length = strlen(default_403_document);
    header->document = (char *)default_403_document;
}

void http_response_404(http_response_t *header)
{
    header->version = HTTP_VERSION_1_1;
    header->status_code = 404;
    dict_put(header->fields, "Server", "httpsrv/1.0");
    dict_put(header->fields, "Content-Type", "text/html; charset=iso-8859-1");
    dict_put(header->fields, "Connection", "closed");
    header->document_length = strlen(default_404_document);
    header->document = (char *)default_404_document;
}

void http_response_200(http_response_t *header)
{
    header->version = HTTP_VERSION_1_1;
    header->status_code = 200;
    dict_put(header->fields, "Server", "httpsrv/1.0");
    dict_put(header->fields, "Content-Type", "text/html; charset=iso-8859-1");
    dict_put(header->fields, "Connection", "closed");
    header->document = NULL;
}

int http_assemble_response(http_response_t *header, int fd)
{
    char outbuf[MAX_REQUEST_SIZE];
    sprintf(outbuf, "%s %d %s\r\nContent-Length: %d\r\n",
        http_version_to_string(header->version), header->status_code,
        http_code_to_string(header->status_code), header->document_length);

    char field[HTTP_MAX_FIELD_LENGTH];
    int i;
    for(i = 0; i < RESPONSE_FIELDS_SIZE; i++) {
        const char *value = dict_get(header->fields, response_fields[i]);
        if(value) {
            sprintf(field, "%s: %s\r\n", response_fields[i], value);
            strcat(outbuf, field);
        }
    }
    strcat(outbuf, "\r\n");
    write(fd, outbuf, strlen(outbuf));
    if(header->document != NULL) {
        write(fd, header->document, header->document_length);
    } else {
        char *buf = (char *)malloc(header->document_length);
        FILE *fp = fopen(header->fname, "r");
        fread(buf, 1, header->document_length, fp);
        fclose(fp);
        write(fd, buf, header->document_length);
        free(buf);
    }
    return 0;
}
