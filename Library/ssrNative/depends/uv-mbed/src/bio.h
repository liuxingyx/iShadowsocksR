//
// Created by eugene on 3/14/19.
// Modified by ssrlive
//
// Basic Input Output, BIO.
//

#ifndef UV_MBED_BIO_H
#define UV_MBED_BIO_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

struct bio;

// zerocopy means that buffer passed into BIO_put will be owned/released by BIO,
// this avoids an extra alloc/copy operation
struct bio* bio_new(bool zerocopy);
bool bio_is_zero_copy(struct bio *);
void bio_reset(struct bio *);
void bio_free(struct bio*);

bool bio_put(struct bio *, const uint8_t *buf, size_t len);
size_t bio_read(struct bio*, uint8_t *buf, size_t len);
size_t bio_available(struct bio*);

#endif //UV_MBED_BIO_H
