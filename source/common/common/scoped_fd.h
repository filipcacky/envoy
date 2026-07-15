#pragma once

#include <memory>

#include "envoy/common/platform.h"

namespace Envoy {

class ScopedFd {
public:
  ScopedFd() = default;
  explicit ScopedFd(os_fd_t fd);
  ~ScopedFd();

  ScopedFd(const ScopedFd&) = delete;
  ScopedFd& operator=(const ScopedFd&) = delete;
  ScopedFd(ScopedFd&& other) noexcept;
  ScopedFd& operator=(ScopedFd&& other) noexcept;

  os_fd_t fd() const;
  bool isValid() const;

private:
  void close();

  os_fd_t fd_{INVALID_SOCKET};
};

using ScopedFdSharedPtr = std::shared_ptr<ScopedFd>;

} // namespace Envoy
