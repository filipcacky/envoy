#pragma once

#include <memory>

#include "envoy/common/platform.h"

namespace Envoy {
namespace Network {

/**
 * RAII owner of an eBPF program file descriptor used for routing packets within a reuseport
 * group. Only owns the descriptor, it does not load programs.
 */
class ReuseportEbpfProgram {
public:
  explicit ReuseportEbpfProgram(os_fd_t fd) : fd_(fd) {}
  ~ReuseportEbpfProgram();

  ReuseportEbpfProgram(const ReuseportEbpfProgram&) = delete;
  ReuseportEbpfProgram& operator=(const ReuseportEbpfProgram&) = delete;
  ReuseportEbpfProgram(ReuseportEbpfProgram&&) = delete;
  ReuseportEbpfProgram& operator=(ReuseportEbpfProgram&&) = delete;

  os_fd_t fd() const { return fd_; }

private:
  const os_fd_t fd_;
};

using ReuseportEbpfProgramSharedPtr = std::shared_ptr<ReuseportEbpfProgram>;

} // namespace Network
} // namespace Envoy
