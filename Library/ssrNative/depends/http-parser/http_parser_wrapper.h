#ifndef __http_parser_wrapper_h__
#define __http_parser_wrapper_h__
#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#if defined(_WIN32) && !defined(__MINGW32__) && \
  (!defined(_MSC_VER) || _MSC_VER<1600) && !defined(__WINE__)
#include <BaseTsd.h>
typedef __int8 int8_t;
typedef unsigned __int8 uint8_t;
typedef __int16 int16_t;
typedef unsigned __int16 uint16_t;
typedef __int32 int32_t;
typedef unsigned __int32 uint32_t;
typedef __int64 int64_t;
typedef unsigned __int64 uint64_t;
#else
#include <stdint.h>
#endif

struct http_headers;

struct http_headers * http_headers_parse(int request, const uint8_t *data, size_t data_len);

size_t http_headers_count(struct http_headers *headers);

const char * http_headers_get_url(struct http_headers *headers);
const char * http_headers_get_status(struct http_headers *headers);

typedef void(*header_walker)(char *key, char *value, int *stop, void *p);
void http_headers_enumerate(struct http_headers *headers, header_walker cb, void *p);

const char * http_headers_get_field_val(const struct http_headers *headers, const char *field);

size_t http_headers_get_content_beginning(const struct http_headers *headers);
size_t http_headers_get_parsed_length(const struct http_headers *headers);

void http_headers_destroy(struct http_headers *headers);

#ifdef __cplusplus
}
#endif
#endif /* __http_parser_wrapper_h__ */
