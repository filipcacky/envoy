#pragma once

#include <linux/types.h>

struct routing_config { // NOLINT(readability-identifier-naming)
  __u8 generation;
  __u8 _pad[3];
  __u32 concurrency;
};
