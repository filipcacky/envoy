#include "source/common/network/reuseport_ebpf_program.h"

namespace Envoy {
namespace Network {

ReuseportEbpfProgram::~ReuseportEbpfProgram() {
  if (SOCKET_VALID(fd_)) {
    ::close(fd_);
  }
}

} // namespace Network
} // namespace Envoy
