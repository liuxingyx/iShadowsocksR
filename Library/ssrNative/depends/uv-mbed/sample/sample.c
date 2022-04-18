//
// Created by eugene on 3/14/19.
//


#include <uv.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <uv-mbed/uv-mbed.h>
#include "cmd_line_parser.h"

#define DEFAULT_CA_CHAIN "/etc/ssl/certs/ca-certificates.crt"

struct client_context {
    struct cmd_line_info *cmd;
    FILE *fp;
    bool header_parsed;
    size_t file_size;
    size_t progress_size;
};

static void on_close(uv_mbed_t *h, void *p) {
    (void)p;
    printf("mbed is closed\n");
    uv_mbed_release((uv_mbed_t *) h);
}

static void alloc(uv_mbed_t *mbed, size_t suggested_size, uv_buf_t *buf) {
    char *base = (char *) calloc(suggested_size, sizeof(char));
    *buf = uv_buf_init(base, suggested_size);
}

void on_data(uv_mbed_t *h, ssize_t nread, uv_buf_t* buf, void *p) {
    struct client_context *ctx = (struct client_context *)p;
    if (nread > 0) {
        if (ctx->fp) {
            char *ptmp = (char *)buf->base;
            size_t len0 = (size_t)nread;
            if (ctx->header_parsed == false) {
#define GET_REQUEST_END "\r\n\r\n"
                char *px = strstr(ptmp, GET_REQUEST_END);
                if (px != NULL) {
                    ptmp = px + strlen(GET_REQUEST_END);
                    len0 = len0 - (size_t)(ptmp - buf->base);
                }
                ctx->header_parsed = true;

#define CONTENT_LENGTH "Content-Length:"
                px = strstr(buf->base, CONTENT_LENGTH);
                if (px) {
                    px = px + strlen(CONTENT_LENGTH);
                    ctx->file_size = (size_t) strtol(px, NULL, 10);
                }
            }
            fwrite(ptmp, len0, 1, ctx->fp);

            if (ctx->file_size) {
                float percent = 0.0;
                ctx->progress_size += len0;
                percent = (float)(ctx->progress_size * 100.0 / ctx->file_size);
                printf("received %6.2f%% of %d bytes\r", percent, (int) ctx->file_size);
                fflush(stdout);
            }
        } else {
            printf("%*.*s", (int) nread, (int) nread, buf->base);
            fflush(stdout);
        }
    } else if (nread == UV_EOF) {
        if (ctx->file_size != 0) {
            printf("\n");
        }
        printf("=====================\nconnection closed\n");
        uv_mbed_close(h, on_close, p);
    } else if (nread != 0) {
        fprintf(stderr, "read error %ld: %s\n", nread, uv_strerror((int) nread));
        uv_mbed_close(h, on_close, p);
    }
    free(buf->base);
}

void write_cb(uv_mbed_t *mbed, int status, void *p) {
    if (status < 0) {
        fprintf(stderr, "write failed: %d: %s\n", status, uv_strerror(status));
        uv_mbed_close(mbed, on_close, p);
    }
    printf("request sent %d\n", status);
}

void on_connect(uv_mbed_t* mbed, int status, void *p) {
    struct client_context *ctx = (struct client_context *)p;
    char req[] = "GET %s HTTP/1.1\r\n"
                 "Accept: */*\r\n"
                 "Connection: close\r\n"
                 "Host: %s\r\n"
                 "User-Agent: HTTPie/1.0.2\r\n"
                 "\r\n";
    char out_buf[512];
    uv_buf_t buf;
    if (status < 0) {
        fprintf(stderr, "connect failed: %d: %s\n", status, uv_strerror(status));
        uv_mbed_close(mbed, on_close, p);
        return;
    }

    uv_mbed_set_read_callback(mbed, alloc, on_data, p);

    sprintf(out_buf, req, ctx->cmd->request_path, ctx->cmd->server_addr);

    buf = uv_buf_init(out_buf, (unsigned int) strlen(out_buf) + 1);
    uv_mbed_write(mbed, &buf, write_cb, p);
}

int main(int argc, char * const argv[]) {
    uv_loop_t *l = uv_default_loop();
    uv_mbed_t *mbed;
    struct cmd_line_info *cmd;
    FILE *fp = NULL;
    struct client_context ctx = { NULL };

    cmd = cmd_line_info_create(argc, argv);

    if (cmd->help_flag) {
        app_usage(argc, argv);
        goto exit_point;
    }

    if (cmd->out_put_file && strlen(cmd->out_put_file)) {
        fp = fopen(cmd->out_put_file, "wb+");
    }

    mbed = uv_mbed_init(l, cmd->server_addr, NULL, cmd->dump_level);

    ctx.cmd = cmd;
    ctx.fp = fp;

    uv_mbed_connect(mbed, cmd->server_addr, atoi(cmd->server_port), 5000, on_connect, &ctx);

    uv_run(l, UV_RUN_DEFAULT);

exit_point:
    cmd_line_info_destroy(cmd);
    if (fp) {
        fclose(fp);
    }
}
