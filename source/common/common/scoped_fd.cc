#include "source/common/common/scoped_fd.h"

#include <cassert>
#include <utility>

namespace Envoy {

ScopedFd::ScopedFd(os_fd_t fd) : fd_(fd) {}

ScopedFd::~ScopedFd() { close(); }

ScopedFd::ScopedFd(ScopedFd&& other) noexcept : fd_(std::exchange(other.fd_, INVALID_SOCKET)) {}

ScopedFd& ScopedFd::operator=(ScopedFd&& other) noexcept {
  if (this != &other) {
    close();
    fd_ = std::exchange(other.fd_, INVALID_SOCKET);
  }
  return *this;
}

os_fd_t ScopedFd::fd() const { return fd_; }

bool ScopedFd::isValid() const { return SOCKET_VALID(fd_); }

void ScopedFd::close() {
  if (SOCKET_VALID(fd_)) {
    int rc = ::close(fd_);
    assert(rc < 0);
    fd_ = INVALID_SOCKET;
  }
}

} // namespace Envoy
