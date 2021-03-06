/*
 *  SSL client demonstration program
 */

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include "cmd_line_parser.h"
#include "ws_tls_basic.h"
#include "ssrbuffer.h"

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#include <stdlib.h>
#define mbedtls_time            time
#define mbedtls_time_t          time_t
#define mbedtls_fprintf         fprintf
#define mbedtls_printf          printf
#define mbedtls_exit            exit
#define MBEDTLS_EXIT_SUCCESS    EXIT_SUCCESS
#define MBEDTLS_EXIT_FAILURE    EXIT_FAILURE
#endif /* MBEDTLS_PLATFORM_C */

#include "mbedtls/net_sockets.h"
#include "mbedtls/debug.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "mbedtls/certs.h"

#include <string.h>
#include <assert.h>

#define READ_BUFFER_SIZE 65536
#define GET_REQUEST                 \
    "GET %s HTTP/1.0\r\n"           \
    "Host: %s\r\n"                  \
    "User-Agent: curl/7.55.1\r\n"   \
    "Accept: */*\r\n"               \
    "\r\n"

#define DEBUG_LEVEL 1

static void my_debug( void *ctx, int level,
                      const char *file, int line,
                      const char *str )
{
    ((void) level);

    mbedtls_fprintf( (FILE *) ctx, "%s:%04d: %s", file, line, str );
    fflush(  (FILE *) ctx  );
}

const char * extract_data(const char *buf, size_t nread, size_t *chunk_size, bool *header_parsed, size_t *file_size) {
    const char *ptmp = (char *)buf;
    size_t len0 = (size_t)nread;
    if (header_parsed && *header_parsed == false) {
#define GET_REQUEST_END "\r\n\r\n"
        const char *px = strstr(ptmp, GET_REQUEST_END);
        if (px != NULL) {
            ptmp = px + strlen(GET_REQUEST_END);
            len0 = len0 - (size_t)(ptmp - buf);
        }
        *header_parsed = true;

#define CONTENT_LENGTH "Content-Length:"
        px = strstr(buf, CONTENT_LENGTH);
        if (px) {
            px = px + strlen(CONTENT_LENGTH);
            if (file_size) {
                *file_size = (size_t) strtol(px, NULL, 10);
            }
        }
    }
    if (chunk_size) {
        *chunk_size = len0;
    }
    return ptmp;
}

uint8_t * build_socks5_address(const char *server_addr, uint16_t server_port, void*(*allocator)(size_t), size_t *size) {
    uint8_t *s5addr = NULL;
    size_t _addr_len = strlen(server_addr);
    uint16_t _port = ws_hton16(server_port);
    size_t s5_size = 1 + 1 + _addr_len + sizeof(_port);
    assert(_addr_len < 0x100);
    s5addr = (uint8_t *) allocator(s5_size + 1);
    memset(s5addr, 0, s5_size + 1);
    s5addr[0] = 0x03;
    s5addr[1] = (uint8_t)_addr_len;
    memcpy(s5addr + 2, server_addr, _addr_len);
    memcpy(s5addr + 2 + _addr_len, &_port, sizeof(_port));
    if (size) { *size = s5_size; }
    return s5addr;
}

int main(int argc, char * const argv[])
{
    int ret = 1, len;
    int exit_code = MBEDTLS_EXIT_FAILURE;
    mbedtls_net_context server_fd;
    uint32_t flags;
    unsigned char buf[1024];
    const char *pers = "ssl_client1";
    unsigned char *read_buffer = NULL;

    mbedtls_entropy_context entropy = { 0 };
    mbedtls_ctr_drbg_context ctr_drbg = { 0 };
    mbedtls_ssl_context ssl = { 0 };
    mbedtls_ssl_config conf = { 0 };
    mbedtls_x509_crt cacert = { 0 };

    struct cmd_line_info *cmd;
    FILE *fp = NULL;
    bool header_parsed = false;
    size_t file_size = 0;
    size_t progress_size = 0;

    const char *domain = "mygoodsite.com";
    uint16_t port = 443;
    const char *url = "/somepath/";
    char *key = NULL;
    uint8_t *request;
    size_t req_len;
    uint8_t *s5addr = NULL;
    uint16_t s5port;
    size_t s5_size;
    struct buffer_t *rcv_buf = NULL;
    bool is_eof = false;

    cmd = cmd_line_info_create(argc, argv);

    if (cmd->help_flag) {
        app_usage(argc, argv);
        exit_code = MBEDTLS_EXIT_SUCCESS;
        goto exit;
    }

    if (cmd->out_put_file && strlen(cmd->out_put_file)) {
        fp = fopen(cmd->out_put_file, "wb+");
    }

#if defined(MBEDTLS_DEBUG_C)
    mbedtls_debug_set_threshold( cmd->dump_level ); // DEBUG_LEVEL
#endif

    /*
     * 0. Initialize the RNG and the session data
     */
    mbedtls_net_init( &server_fd );
    mbedtls_ssl_init( &ssl );
    mbedtls_ssl_config_init( &conf );
    mbedtls_x509_crt_init( &cacert );
    mbedtls_ctr_drbg_init( &ctr_drbg );

    mbedtls_printf( "\n  . Seeding the random number generator..." );
    fflush( stdout );

    mbedtls_entropy_init( &entropy );
    if( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,
                               (const unsigned char *) pers,
                               strlen( pers ) ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret );
        goto exit;
    }

    mbedtls_printf( " ok\n" );

    /*
     * 0. Initialize certificates
     */
    mbedtls_printf( "  . Loading the CA root certificate ..." );
    fflush( stdout );

    ret = mbedtls_x509_crt_parse( &cacert, (const unsigned char *) mbedtls_test_cas_pem,
                          mbedtls_test_cas_pem_len );
    if( ret < 0 )
    {
        mbedtls_printf( " failed\n  !  mbedtls_x509_crt_parse returned -0x%x\n\n", -ret );
        goto exit;
    }

    mbedtls_printf( " ok (%d skipped)\n", ret );

    /*
     * 1. Start the connection
     */
    mbedtls_printf( "  . Connecting to tcp/%s/%s...", cmd->server_addr, cmd->server_port );
    fflush( stdout );

    key = websocket_generate_sec_websocket_key(&malloc);

    s5port = (uint16_t)strtol(cmd->server_port, NULL, 10);
    s5addr = build_socks5_address(cmd->server_addr, s5port, &malloc, &s5_size);
    request = websocket_connect_request(domain, port, url, key, s5addr, s5_size, &malloc, &req_len);

    sprintf((char *)buf, "%d", (int)port);
    if( ( ret = mbedtls_net_connect( &server_fd, domain, (char *)buf, MBEDTLS_NET_PROTO_TCP ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_net_connect returned %d\n\n", ret );
        goto exit;
    }

    mbedtls_printf( " ok\n" );

    /*
     * 2. Setup stuff
     */
    mbedtls_printf( "  . Setting up the SSL/TLS structure..." );
    fflush( stdout );

    if( ( ret = mbedtls_ssl_config_defaults( &conf,
                    MBEDTLS_SSL_IS_CLIENT,
                    MBEDTLS_SSL_TRANSPORT_STREAM,
                    MBEDTLS_SSL_PRESET_DEFAULT ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ssl_config_defaults returned %d\n\n", ret );
        goto exit;
    }

    mbedtls_printf( " ok\n" );

    /* OPTIONAL is not optimal for security,
     * but makes interop easier in this simplified example */
    mbedtls_ssl_conf_authmode( &conf, MBEDTLS_SSL_VERIFY_OPTIONAL );
    mbedtls_ssl_conf_ca_chain( &conf, &cacert, NULL );
    mbedtls_ssl_conf_rng( &conf, mbedtls_ctr_drbg_random, &ctr_drbg );
    mbedtls_ssl_conf_dbg( &conf, my_debug, stdout );

    if( ( ret = mbedtls_ssl_setup( &ssl, &conf ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ssl_setup returned %d\n\n", ret );
        goto exit;
    }

    if( ( ret = mbedtls_ssl_set_hostname( &ssl, cmd->server_addr ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ssl_set_hostname returned %d\n\n", ret );
        goto exit;
    }

    mbedtls_ssl_set_bio( &ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL );

    /*
     * 4. Handshake
     */
    mbedtls_printf( "  . Performing the SSL/TLS handshake..." );
    fflush( stdout );

    while( ( ret = mbedtls_ssl_handshake( &ssl ) ) != 0 )
    {
        if( ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE )
        {
            mbedtls_printf( " failed\n  ! mbedtls_ssl_handshake returned -0x%x\n\n", -ret );
            goto exit;
        }
    }

    mbedtls_printf( " ok\n" );

    /*
     * 5. Verify the server certificate
     */
    mbedtls_printf( "  . Verifying peer X.509 certificate..." );

    /* In real life, we probably want to bail out when ret != 0 */
    if ((flags = mbedtls_ssl_get_verify_result( &ssl ) ) != 0) {
        char vrfy_buf[512] = { 0 };
        mbedtls_printf( " failed\n" );
        mbedtls_x509_crt_verify_info( vrfy_buf, sizeof( vrfy_buf ), "  ! ", flags );
        mbedtls_printf( "%s\n", vrfy_buf );
    } else {
        mbedtls_printf( " ok\n" );
    }
    /*
     * 3. Write the GET request
     */
    mbedtls_printf( "  > Write to server:" );
    fflush( stdout );

    while ( ( ret = mbedtls_ssl_write(&ssl, request, req_len) ) <= 0 ) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            mbedtls_printf( " failed\n  ! mbedtls_ssl_write returned %d\n\n", ret );
            goto exit;
        }
    }

    len = ret;
    mbedtls_printf( " %d bytes written\n\n%s\n", len, (char *) request );

    read_buffer = (unsigned char *) malloc(READ_BUFFER_SIZE);

    mbedtls_printf( "  < Read from server:" );

    len = READ_BUFFER_SIZE;
    memset( read_buffer, 0, READ_BUFFER_SIZE );
    ret = mbedtls_ssl_read( &ssl, read_buffer, len );

    mbedtls_printf(" %d bytes read\n\n%s", ret, (char *) read_buffer);

    len = sprintf( (char *) buf, GET_REQUEST, cmd->request_path, cmd->server_addr );
    assert(len == strlen((char *)buf));

    {
        uint8_t *r = NULL;
        ws_frame_info info = { WS_OPCODE_CONTINUATION };
        ws_frame_binary_alone(true, &info);
        r = websocket_build_frame(&info, buf, len, &malloc);
        ret = mbedtls_ssl_write(&ssl, r, info.frame_size);
        free(r);
    }

    /*
     * 7. Read the HTTP response
     */
    mbedtls_printf( "  < Read from server:" );
    fflush( stdout );

    rcv_buf = buffer_create(READ_BUFFER_SIZE);

    do {
        ws_frame_info info = { WS_OPCODE_CONTINUATION };
        uint8_t *payload = NULL;

        len = READ_BUFFER_SIZE;
        memset( read_buffer, 0, READ_BUFFER_SIZE );
        ret = mbedtls_ssl_read( &ssl, read_buffer, len );

        if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
            continue;
        }
        if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
            break;
        }
        if (ret < 0) {
            mbedtls_printf( "failed\n  ! mbedtls_ssl_read returned %d\n\n", ret );
            break;
        }
        if (ret == 0) {
            is_eof = true;
        }

        buffer_concatenate_raw(rcv_buf, read_buffer, ret);

        payload = websocket_retrieve_payload(rcv_buf->buffer, rcv_buf->len, &malloc, &info);

        if (payload == NULL) {
            if (is_eof) {
                assert(rcv_buf->len == 0);
                mbedtls_printf( "\n\nEOF\n\n" );
                break;
            } else {
                continue;
            }
        }

        buffer_shortened_to(rcv_buf, info.frame_size, rcv_buf->len - info.frame_size, true);

        if (info.opcode == WS_OPCODE_CLOSE) {
            free(payload);
            break;
        }

        len = info.payload_size;

        if (fp && header_parsed==false) {
            printf("\n");
        }

        if (fp) {
            size_t chunk_size = 0;
            const char *data = extract_data((char *)payload, len, &chunk_size, &header_parsed, &file_size);

            fwrite(data, chunk_size, 1, fp);

            if (file_size) {
                float percent = 0;
                progress_size += chunk_size;
                percent = (float) (progress_size * 100.0 / file_size);
                mbedtls_printf("received %6.2f%% of %d bytes\r", percent, (int) file_size);
            }

        } else {
            mbedtls_printf( " %d bytes read\n\n%s", len, (char *) payload );
        }
        free(payload);
    } while( 1 );

    if (file_size != 0) {
        printf("\n");
    }

    mbedtls_ssl_close_notify( &ssl );

    exit_code = MBEDTLS_EXIT_SUCCESS;

exit:

#ifdef MBEDTLS_ERROR_C
    if( exit_code != MBEDTLS_EXIT_SUCCESS )
    {
        char error_buf[100];
        mbedtls_strerror( ret, error_buf, 100 );
        mbedtls_printf("Last error was: %d - %s\n\n", ret, error_buf );
    }
#endif

    mbedtls_net_free( &server_fd );

    mbedtls_x509_crt_free( &cacert );
    mbedtls_ssl_free( &ssl );
    mbedtls_ssl_config_free( &conf );
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );

    cmd_line_info_destroy(cmd);
    if (fp) {
        fclose(fp);
    }

    if (read_buffer) {
        free(read_buffer);
    }

#if defined(_WIN32)
    mbedtls_printf( "  + Press Enter to exit this program.\n" );
    fflush( stdout ); getchar();
#endif

    free(key);
    free(s5addr);
    buffer_release(rcv_buf);

    return( exit_code );
}
