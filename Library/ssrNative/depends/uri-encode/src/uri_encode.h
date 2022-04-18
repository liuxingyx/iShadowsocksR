#ifndef __URI_ENCODE_C_H__
#define __URI_ENCODE_C_H__

#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

#define URI_ENCODE_BUFF_SIZE_MAX(src_len) ((src_len) * 3 + 1)

size_t uri_encode_buffer_size(const char* src, size_t src_len);
size_t uri_encode (const char *src, size_t src_len, char *dst, size_t dst_len);
size_t uri_decode(const char* src, char* dst, size_t dst_len);

#ifdef __cplusplus
}
#endif

#endif // __URI_ENCODE_C_H__
