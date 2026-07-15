#pragma once

#include <stdint.h> // NOLINT(modernize-deprecated-headers): shared with the BPF C program.

// NOLINT(namespace-envoy)

// The maximum number of workers. The worker index is a single connection ID byte.
#define EPOCH_STABLE_MAX_WORKERS 256

struct routing_config { // NOLINT(readability-identifier-naming)
  uint8_t generation;
  uint8_t _pad[3];
  uint32_t concurrency;
};
