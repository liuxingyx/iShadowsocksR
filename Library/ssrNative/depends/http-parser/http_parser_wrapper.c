#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "http_parser.h"
#include "http_parser_wrapper.h"

#define MAX_HTTP_HEADERS 8

struct http_header {
    char *key;
    char *value;
};

struct http_headers {
    size_t capacity;
    size_t count;
    struct http_header *headers;
    int complete;
    char *url;
    char *status;
    size_t content_beginning;
    size_t parsed_len;
    uint8_t *origin_data; /* weak pointer */
    size_t origin_data_len;
};


static int on_message_begin(http_parser *parser) {
    (void)parser;
    return 0;
}

static int on_headers_complete(http_parser *parser) {
    struct http_headers *hdrs = (struct http_headers *) parser->data;
    hdrs->complete = 1;
    return 0;
}

static int on_message_complete(http_parser *parser) {
    (void)parser;
    return 0;
}

static int on_chunk_header(http_parser *parser) {
    (void)parser;
    return 0;
}

static int on_chunk_complete(http_parser *parser) {
    (void)parser;
    return 0;
}

static int on_url(http_parser *parser, const char *at, size_t length) {
    struct http_headers *hdrs = (struct http_headers *)parser->data;
    hdrs->url = (char *) calloc(length + 1, sizeof(char));
    strncpy(hdrs->url, at, length);
    return 0;
}

static int on_status(http_parser* parser, const char *at, size_t length) {
    struct http_headers *hdrs = (struct http_headers *)parser->data;
    hdrs->status = (char *) calloc(length + 1, sizeof(char));
    strncpy(hdrs->status, at, length);
    return 0;
}

static int on_header_field(http_parser* parser, const char *at, size_t length) {
    struct http_headers *hdrs = (struct http_headers *)parser->data;
    char *key;

    if (hdrs->count >= hdrs->capacity) {
        if (hdrs->capacity == 0) {
            assert(hdrs->headers == NULL);
            hdrs->capacity = MAX_HTTP_HEADERS;
            hdrs->headers = (struct http_header *)
                calloc(hdrs->capacity, sizeof(struct http_header));
        } else {
            hdrs->capacity *= 2;
            hdrs->headers = (struct http_header *)
                realloc(hdrs->headers, hdrs->capacity * sizeof(struct http_header));
        }
    }

    key = (char *) calloc(1, length + 1);
    strncpy(key, at, length);

    hdrs->headers[hdrs->count].key = key;

    return 0;
}

static int on_header_value(http_parser* parser, const char *at, size_t length) {
    struct http_headers *hdrs = (struct http_headers *) parser->data;

    char *value = (char *) calloc(1, length + 1);
    strncpy(value, at, length);

    hdrs->headers[hdrs->count].value = value;
    hdrs->count++;

    return 0;
}

static int on_body(http_parser* parser, const char *at, size_t length) {
    struct http_headers *hdrs = (struct http_headers *) parser->data;
    (void)length;
    hdrs->content_beginning = (uint8_t *)at - hdrs->origin_data;
    // assert(hdrs->origin_data_len == length + hdrs->content_beginning);
    return 0;
}

size_t http_headers_count(struct http_headers *headers) {
    return headers->count;
}

const char * http_headers_get_url(struct http_headers *headers) {
    return headers->url;
}

const char * http_headers_get_status(struct http_headers *headers) {
    return headers->status;
}

void http_headers_enumerate(struct http_headers *headers, header_walker cb, void *p) {
    size_t i;
    if (headers==NULL || cb==NULL) {
        return;
    }
    for(i = 0; i < headers->count; i++) {
        struct http_header *h = headers->headers + i;
        int stop = 0;
        cb(h->key, h->value, &stop, p);
        if (stop) { break; }
    }
}

void http_headers_get_field_val_cb(char *key, char *value, int *stop, void *p) {
    struct http_header *data = (struct http_header*)p;
#ifdef _MSC_VER
#define strcasecmp _stricmp
#endif
    if (strcasecmp(key, data->key) == 0) {
        data->value = value;
        if (stop) { *stop = 1; }
    }
}

const char * http_headers_get_field_val(const struct http_headers *headers, const char *field) {
    struct http_header data = { (char *)field, NULL };
    http_headers_enumerate((struct http_headers *)headers, http_headers_get_field_val_cb, &data);
    return data.value;
}

size_t http_headers_get_content_beginning(const struct http_headers *headers) {
    return headers->content_beginning;
}

size_t http_headers_get_parsed_length(const struct http_headers *headers) {
    return headers->parsed_len;
}

void http_headers_destroy_cb(char *key, char *value, int *stop, void *p) {
    (void)stop; (void)p;
    free(key);
    free(value);
}

void http_headers_destroy(struct http_headers *headers) {
    if (headers == NULL) {
        return;
    }
    if (headers->url) { free(headers->url); }
    if (headers->status) { free(headers->status); }
    if (headers->headers) {
        http_headers_enumerate(headers, http_headers_destroy_cb, NULL);
        free(headers->headers);
    }
    free(headers);
}

static http_parser_settings settings = {
    on_message_begin,
    on_url,
    on_status,
    on_header_field,
    on_header_value,
    on_headers_complete,
    on_body,
    on_message_complete,
    on_chunk_header,
    on_chunk_complete,
};

static const uint8_t * memory_search(const uint8_t *mem, size_t size, const uint8_t *submem, size_t subsize);

struct http_headers * http_headers_parse(int request, const uint8_t *data, size_t data_len) {
    struct http_parser parser = { 0 };
    size_t parsed;
    struct http_headers *hdrs;
    hdrs = (struct http_headers *) calloc(1, sizeof(struct http_headers));
    hdrs->origin_data = (uint8_t *)data;
    hdrs->origin_data_len = data_len;
    hdrs->content_beginning = data_len;
    parser.data = hdrs;
    http_parser_init(&parser, request ? HTTP_REQUEST : HTTP_RESPONSE);

    parsed = http_parser_execute(&parser, &settings, (char *)data, data_len);
    hdrs->parsed_len = parsed;
    if (parsed != 0 && (parsed != data_len)) {
#define GET_REQUEST_END "\r\n\r\n"
        const uint8_t *hdr_end =
            memory_search(data, data_len, (const uint8_t *)GET_REQUEST_END, strlen(GET_REQUEST_END));
        if (hdr_end) {
            hdr_end += strlen(GET_REQUEST_END);
            hdrs->content_beginning = hdr_end - data;
        }
    }

    return hdrs;
}

static const uint8_t * memory_search(const uint8_t *mem, size_t size, const uint8_t *submem, size_t subsize) {
    const uint8_t *end = mem + (size - subsize);
    if (mem==NULL || size==0 || submem==NULL || subsize==0) {
        return NULL;
    }
    while (mem != end) {
        if (memcmp(mem, submem, subsize) == 0) {
            return mem;
        }
        ++mem;
    }
    return NULL;
}
