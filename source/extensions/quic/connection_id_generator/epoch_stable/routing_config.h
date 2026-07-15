#pragma once

#include <linux/types.h>

// NOLINT(namespace-envoy)

// The maximum number of workers. The worker index is a single connection ID byte.
#define EPOCH_STABLE_MAX_WORKERS 256

struct routing_config { // NOLINT(readability-identifier-naming)
  __u8 generation;
  __u8 _pad[3];
  __u32 concurrency;
};
