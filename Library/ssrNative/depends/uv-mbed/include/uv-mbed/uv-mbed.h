//
// Created by eugene on 3/14/19.
//

#ifndef UV_MBED_H
#define UV_MBED_H

#include <uv.h>

#ifdef __cplusplus
extern "C" {
#endif

struct uv_mbed_s;
typedef struct uv_mbed_s uv_mbed_t;

uv_mbed_t * uv_mbed_init(uv_loop_t *loop, const char *host_name, void *user_data, int dump_level);
int uv_mbed_add_ref(uv_mbed_t *mbed);
int uv_mbed_release(uv_mbed_t *mbed);
void * uv_mbed_user_data(uv_mbed_t *mbed);
uv_os_sock_t uv_mbed_get_stream_fd(const uv_mbed_t *mbed);

typedef void (*uv_mbed_connect_cb)(uv_mbed_t* mbed, int status, void *p);
int uv_mbed_connect(uv_mbed_t* mbed, const char *remote_addr, int port, uint64_t timeout_milliseconds, uv_mbed_connect_cb cb, void *p);

typedef void (*uv_mbed_tcp_connect_established_cb)(uv_mbed_t* mbed, void *p);
void uv_mbed_set_tcp_connect_established_callback(uv_mbed_t* mbed, uv_mbed_tcp_connect_established_cb cb, void *p);

typedef void (*uv_mbed_alloc_cb)(uv_mbed_t *mbed, size_t suggested_size, uv_buf_t* buf);
typedef void (*uv_mbed_read_cb)(uv_mbed_t *mbed, ssize_t nread, uv_buf_t* buf, void *p);
void uv_mbed_set_read_callback(uv_mbed_t *mbed, uv_mbed_alloc_cb, uv_mbed_read_cb, void*);

typedef void (*uv_mbed_write_cb)(uv_mbed_t *mbed, int status, void *p);
int uv_mbed_write(uv_mbed_t *mbed, const uv_buf_t *buf, uv_mbed_write_cb cb, void *p);

int uv_mbed_is_closing(uv_mbed_t *mbed);

typedef void (*uv_mbed_close_cb)(uv_mbed_t *mbed, void *p);
int uv_mbed_close(uv_mbed_t *mbed, uv_mbed_close_cb close_cb, void *p);

#ifdef __cplusplus
}
#endif

#endif //UV_MBED_H
