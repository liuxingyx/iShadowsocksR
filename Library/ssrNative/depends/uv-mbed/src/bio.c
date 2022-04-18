//
// Created by eugene on 3/14/19.
// Modified by ssrlive
//

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/queue.h>
#include "bio.h"

struct bio_msg {
    size_t len;
    uint8_t *buf;

    STAILQ_ENTRY(bio_msg) next;
};

struct bio {
    size_t available;
    size_t headoffset;
    bool zerocopy;
    STAILQ_HEAD(msgq, bio_msg) message_q;
};

struct bio * bio_new(bool zerocopy) {
    struct bio *bio = (struct bio*) calloc(1, sizeof(*bio));
    bio->available = 0;
    bio->headoffset = 0;
    bio->zerocopy = zerocopy;

    STAILQ_INIT(&bio->message_q);
    return bio;
}

bool bio_is_zero_copy(struct bio *b) {
    return b->zerocopy;
}

void bio_reset(struct bio *b) {
    while(!STAILQ_EMPTY(&b->message_q)) {
        struct bio_msg *m = STAILQ_FIRST(&b->message_q);
        STAILQ_REMOVE_HEAD(&b->message_q, next);
        free(m->buf);
        free(m);
    }
    b->available = 0;
    b->headoffset = 0;
}

void bio_free(struct bio *b) {
    bio_reset(b);
    free(b);
}

size_t bio_available(struct bio *bio) {
    return bio->available;
}

bool bio_put(struct bio *bio, const uint8_t *buf, size_t len) {
    struct bio_msg *m = (struct bio_msg *) calloc(1, sizeof(struct bio_msg));
    if (m == NULL) {
        return false;
    }

    if (bio->zerocopy) {
        m->buf = (uint8_t *) buf;
    } else {
        m->buf = (uint8_t *) calloc(len, sizeof(uint8_t));
        if (m->buf == NULL) {
            free(m);
            return false;
        }
        memcpy(m->buf, buf, len);
    }

    m->len = len;

    STAILQ_INSERT_TAIL(&bio->message_q, m, next);
    bio->available += len;

    return true;
}

size_t bio_read(struct bio *bio, uint8_t *buf, size_t len) {

    size_t total = 0;

    while (! STAILQ_EMPTY(&bio->message_q) && total < len) {
        struct bio_msg *m = STAILQ_FIRST(&bio->message_q);

#ifndef MIN
#define MIN(a,b) (((a)<(b))?(a):(b))
#endif

        size_t recv_size = MIN(len - total, m->len - bio->headoffset);
        memcpy(buf + total, m->buf + bio->headoffset, recv_size);
        bio->headoffset += recv_size;
        bio->available -= recv_size;
        total += recv_size;

        if (bio->headoffset == m->len) {
            STAILQ_REMOVE_HEAD(&bio->message_q, next);
            bio->headoffset = 0;

            free(m->buf);
            free(m);
        }
    }

    return total;
}
