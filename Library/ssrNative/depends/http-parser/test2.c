#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "http_parser_wrapper.h"

/* 8 gb */
static const int64_t kBytes = 8LL << 30;

static const char data[] =
    "POST /joyent/http-parser HTTP/1.1\r\n"
    "Host: github.com\r\n"
    "DNT: 1\r\n"
    "Accept-Encoding: gzip, deflate, sdch\r\n"
    "Accept-Language: ru-RU,ru;q=0.8,en-US;q=0.6,en;q=0.4\r\n"
    "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/39.0.2171.65 Safari/537.36\r\n"
    "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,"
        "image/webp,*/*;q=0.8\r\n"
    "Referer: https://github.com/joyent/http-parser\r\n"
    "Connection: keep-alive\r\n"
    "Transfer-Encoding: chunked\r\n"
    "Cache-Control: max-age=0\r\n"
    "\r\n"
    "b\r\n"
    "hello world\r\n"
    "0\r\n";
static const size_t data_len = sizeof(data) - 1;

static const char data2[] =
    "GET /favicon.ico HTTP/1.1\r\n"
    "Host: 0.0.0.0=5000\r\n"
    "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9) Gecko/2008061015 Firefox/3.0\r\n"
    "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
    "Accept-Language: en-us,en;q=0.5\r\n"
    "Accept-Encoding: gzip,deflate\r\n"
    "Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7\r\n"
    "Keep-Alive: 300\r\n"
    "Connection: keep-alive\r\n"
    "\r\n";
static const size_t data2_len = sizeof(data2) - 1;

static const char data3[] =
    "GET /get_funky_content_length_body_hello HTTP/1.0\r\n"
    "conTENT-Length: 5\r\n"
    "\r\n"
    "HELLO";
static const size_t data3_len = sizeof(data3) - 1;

static const char data4[] =
    "POST /post_identity_body_world?q=search#hey HTTP/1.1\r\n"
    "Accept: */*\r\n"
    "Transfer-Encoding: identity\r\n"
    "Content-Length: 5\r\n"
    "\r\n"
    "World";
static const size_t data4_len = sizeof(data4) - 1;

static const char data5[] =
    "POST /two_chunks_mult_zero_end HTTP/1.1\r\n"
    "Transfer-Encoding: chunked\r\n"
    "\r\n"
    "5\r\n"
    "hello\r\n"
    "6\r\n"
    " world\r\n"
    "000\r\n"
    "\r\n";
static const size_t data5_len = sizeof(data5) - 1;

static const char data6[] =
    "HTTP/1.1 301 Moved Permanently\r\n"
    "Location: http://www.google.com/\r\n"
    "Content-Type: text/html; charset=UTF-8\r\n"
    "Date: Sun, 26 Apr 2009 11:11:49 GMT\r\n"
    "Expires: Tue, 26 May 2009 11:11:49 GMT\r\n"
    "X-$PrototypeBI-Version: 1.6.0.3\r\n" /* $ char in header field */
    "Cache-Control: public, max-age=2592000\r\n"
    "Server: gws\r\n"
    "Content-Length:  219  \r\n"
    "\r\n"
    "<HTML><HEAD><meta http-equiv=\"content-type\" content=\"text/html;charset=utf-8\">\n"
    "<TITLE>301 Moved</TITLE></HEAD><BODY>\n"
    "<H1>301 Moved</H1>\n"
    "The document has moved\n"
    "<A HREF=\"http://www.google.com/\">here</A>.\r\n"
    "</BODY></HTML>\r\n";
static const size_t data6_len = sizeof(data6) - 1;

static const char data7[] =
    "HTTP/1.1 101 Switching Protocols\r\n"
    "Server: nginx/1.17.0\r\n"
    "Date: Fri, 19 Jul 2019 08:47:19 GMT\r\n"
    "Connection: upgrade\r\n"
    "Upgrade: websocket\r\n"
    "Sec-WebSocket-Accept: VWwDIBVDiS1C7IvkdC2eYvlC38M=\r\n"
    "\r\n"
    "\x90\x03\x08\x09";
static const size_t data7_len = sizeof(data7) - 1;

int main(int argc, char** argv) {
    int64_t iterations;
    int i;

    iterations = kBytes / (int64_t) data_len;

    for (i = 0; i < iterations; i++) {
        struct http_headers *p;
        p = http_headers_parse(1, (uint8_t *)data, data_len);
        http_headers_get_field_val(p, "User-Agent");
        printf("data1 body beginning %d\n", (int)http_headers_get_content_beginning(p));
        http_headers_destroy(p);

        p = http_headers_parse(1, (uint8_t *)data2, data2_len);
        http_headers_get_field_val(p, "User-Agent");
        printf("data2 body beginning %d\n", (int)http_headers_get_content_beginning(p));
        http_headers_destroy(p);

        p = http_headers_parse(1, (uint8_t *)data3, data3_len);
        http_headers_get_field_val(p, "User-Agent");
        printf("data3 body beginning %d\n", (int)http_headers_get_content_beginning(p));
        http_headers_destroy(p);

        p = http_headers_parse(1, (uint8_t *)data4, data4_len);
        http_headers_get_field_val(p, "User-Agent");
        printf("data4 body beginning %d\n", (int)http_headers_get_content_beginning(p));
        http_headers_destroy(p);

        p = http_headers_parse(1, (uint8_t *)data5, data5_len);
        http_headers_get_field_val(p, "User-Agent");
        printf("data5 body beginning %d\n", (int)http_headers_get_content_beginning(p));
        http_headers_destroy(p);

        p = http_headers_parse(0, (uint8_t *)data6, data6_len);
        http_headers_get_field_val(p, "Content-Length");
        printf("data6 body beginning %d\n", (int)http_headers_get_content_beginning(p));
        http_headers_destroy(p);

        p = http_headers_parse(0, (uint8_t *)data7, data7_len);
        http_headers_get_field_val(p, "Content-Length");
        printf("data7 body beginning %d\n", (int)http_headers_get_content_beginning(p));
        http_headers_destroy(p);

        printf("=====================================\n");
    }
}
