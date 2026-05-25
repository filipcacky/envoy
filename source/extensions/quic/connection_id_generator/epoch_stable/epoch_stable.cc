#include "source/extensions/quic/connection_id_generator/epoch_stable/epoch_stable.h"

#include "source/common/network/socket_option_impl.h"

#if defined(__linux__)
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <sys/stat.h>

#include "source/extensions/quic/connection_id_generator/epoch_stable/route_bpf_embedded.h"
#endif

namespace Envoy {
namespace Quic {
namespace Extensions {
namespace ConnectionIdGenerator {
namespace EpochStable {

EpochStableConnectionIdObserver::EpochStableConnectionIdObserver(os_fd_t socket_map_fd,
                                                                 uint32_t concurrency)
    : socket_map_fd_(socket_map_fd), concurrency_(concurrency) {
#if not defined(__linux__)
  UNREFERENCED_PARAMETER(socket_map_fd_);
  UNREFERENCED_PARAMETER(concurrency_);
#endif
}

uint64_t EpochStableConnectionIdObserver::cidToKey(const quic::QuicConnectionId& cid) {
  uint64_t key = 0;
  size_t len = std::min<size_t>(cid.length(), sizeof(key));
  memcpy(&key, cid.data(), len); // NOLINT(safe-memcpy)
  return key;
}

void EpochStableConnectionIdObserver::onConnectionIdIssued(
    const quic::QuicConnectionId& connection_id, const Network::Socket& socket) {
#if defined(__linux__)
  uint64_t key = cidToKey(connection_id);
  auto socket_fd = socket.ioHandle().fdDoNotUse();
  int rc = bpf_map_update_elem(socket_map_fd_, &key, &socket_fd, BPF_ANY);
  if (rc < 0) {
    ENVOY_LOG_MISC(warn, "epoch_stable: onConnectionCreated failed key={} fd={} rc={}: {}", key,
                   socket_fd, rc, errorDetails(errno));
  }
#else
  UNREFERENCED_PARAMETER(connection_id);
  UNREFERENCED_PARAMETER(socket);
#endif
}

void EpochStableConnectionIdObserver::onConnectionIdRetired(
    const quic::QuicConnectionId& connection_id) {
#if defined(__linux__)
  uint64_t key = cidToKey(connection_id);
  if (key < concurrency_) {
    return;
  }
  int rc = bpf_map_delete_elem(socket_map_fd_, &key);
  if (rc < 0 && errno != ENOENT) {
    ENVOY_LOG_MISC(warn, "epoch_stable: onConnectionClosed failed key={} rc={} errno={}", key, rc,
                   errorDetails(errno));
  }
#else
  UNREFERENCED_PARAMETER(connection_id);
#endif
}

Factory::Factory(const EpochStableConfig& config) : config_(config) {}

Factory::~Factory() {
#if defined(__linux__)
  if (socket_map_fd_ >= 0) {
    close(socket_map_fd_);
  }
  if (concurrency_fd_ >= 0) {
    close(concurrency_fd_);
  }
  if (prog_fd_ >= 0) {
    close(prog_fd_);
  }
#endif
}

absl::StatusOr<std::unique_ptr<Factory>> Factory::create(const EpochStableConfig& config) {
  return std::unique_ptr<Factory>(new Factory(config));
}

absl::Status Factory::loadMaps(os_fd_t prog_fd) {
#if defined(__linux__)
  bpf_prog_info info{};
  __u32 info_len = sizeof(info);
  std::array<uint32_t, 8> map_ids{};
  info.nr_map_ids = map_ids.size();
  info.map_ids = reinterpret_cast<__u64>(map_ids.data());

  if (bpf_prog_get_info_by_fd(prog_fd, &info, &info_len) < 0) {
    return absl::InternalError(fmt::format("failed to query program: {}", errorDetails(errno)));
  }

  for (__u32 i = 0; i < info.nr_map_ids; i++) {
    int map_fd = bpf_map_get_fd_by_id(map_ids[i]);
    if (map_fd < 0) {
      return cleanupAndError(
          fmt::format("failed to open map id {}: {}", map_ids[i], errorDetails(errno)));
    }

    bpf_map_info map_info{};
    __u32 map_info_len = sizeof(map_info);
    if (bpf_map_get_info_by_fd(map_fd, &map_info, &map_info_len) < 0) {
      return cleanupAndError("failed to query map info");
    }

    if (strcmp(map_info.name, "socket_map") == 0) {
      socket_map_fd_ = map_fd;
    } else if (strcmp(map_info.name, "concurrency") == 0) {
      concurrency_fd_ = map_fd;
    } else {
      close(map_fd);
    }
  }

  if (socket_map_fd_ < 0 || concurrency_fd_ < 0) {
    return cleanupAndError("program missing required maps");
  }

  return absl::OkStatus();
#else
  UNREFERENCED_PARAMETER(prog_fd);
  return absl::UnimplementedError(
      "envoy.quic.epoch_stable_routing_connection_id_generator not available");
#endif
}

QuicConnectionIdGeneratorPtr Factory::createQuicConnectionIdGenerator(uint32_t) {
  return std::make_unique<quic::DeterministicConnectionIdGenerator>(
      quic::kQuicDefaultConnectionIdLength);
}

absl::StatusOr<Network::Socket::OptionConstSharedPtr>
Factory::createCompatibleLinuxBpfSocketOption(uint32_t concurrency, os_fd_t prog_fd) {
#if defined(SO_ATTACH_REUSEPORT_EBPF) && defined(__linux__)
  concurrency_ = concurrency;

  prog_fd_ = prog_fd;
  if (prog_fd_ != INVALID_SOCKET) {
    const auto maps_status = loadMaps(prog_fd_);
    RETURN_IF_NOT_OK_REF(maps_status);
    ENVOY_LOG_MISC(error, "loaded maps");
    return nullptr;
  }

  RETURN_IF_NOT_OK(loadBpfProgram());

  ENVOY_LOG_MISC(info, "epoch_stable: prog_fd={} socket_map_fd={} concurrency_fd={}", prog_fd_,
                 socket_map_fd_, concurrency_fd_);

  return std::make_shared<Network::SocketOptionImpl>(
      envoy::config::core::v3::SocketOption::STATE_BOUND, ENVOY_ATTACH_REUSEPORT_EBPF, prog_fd_);
#else
  UNREFERENCED_PARAMETER(prog_fd);
  UNREFERENCED_PARAMETER(concurrency);
  return absl::UnimplementedError(
      "envoy.quic.epoch_stable_routing_connection_id_generator not available");
#endif
}

absl::Status Factory::loadBpfProgram() {
#if defined(__linux__)
  auto bpf_obj = bpf_object__open_mem(route_bpf_data, route_bpf_data_len, nullptr);
  if (bpf_obj == nullptr) {
    return absl::InternalError(fmt::format("bpf_object__open_mem: {}", errorDetails(errno)));
  }

  struct bpf_map* socket_map = bpf_object__find_map_by_name(bpf_obj, "socket_map");
  if (socket_map == nullptr) {
    return cleanupAndError("socket_map not found in BPF object");
  }

  if (bpf_map__set_max_entries(socket_map, config_.max_map_entries) < 0) {
    return cleanupAndError(fmt::format("bpf_map__set_max_entries: {}", errorDetails(errno)));
  }

  if (bpf_object__load(bpf_obj) < 0) {
    return cleanupAndError(fmt::format("bpf_object__load: {}", errorDetails(errno)));
  }

  struct bpf_program* prog =
      bpf_object__find_program_by_name(bpf_obj, "epoch_stable_select_socket");
  if (prog == nullptr) {
    return cleanupAndError("epoch_stable_select_socket not found");
  }

  prog_fd_ = bpf_program__fd(prog);
  if (prog_fd_ < 0) {
    return cleanupAndError("failed to get program fd");
  }

  socket_map_fd_ = bpf_map__fd(bpf_object__find_map_by_name(bpf_obj, "socket_map"));
  concurrency_fd_ = bpf_map__fd(bpf_object__find_map_by_name(bpf_obj, "concurrency"));

  if (socket_map_fd_ < 0 || concurrency_fd_ < 0) {
    return cleanupAndError("failed to get map fds");
  }

  return absl::OkStatus();
#else
  return absl::UnavailableError("eBPF not supported");
#endif
}

absl::Status Factory::cleanupAndError(absl::string_view message) {
#if defined(__linux__)
  if (socket_map_fd_ >= 0) {
    close(socket_map_fd_);
    socket_map_fd_ = INVALID_SOCKET;
  }
  if (concurrency_fd_ >= 0) {
    close(concurrency_fd_);
    concurrency_fd_ = INVALID_SOCKET;
  }
  if (prog_fd_ >= 0) {
    close(prog_fd_);
    prog_fd_ = INVALID_SOCKET;
  }
  return absl::InternalError(fmt::format("epoch_stable: {}", message));
#else
  UNREFERENCED_PARAMETER(message);
  return absl::OkStatus();
#endif
}

void Factory::registerWorkerSocket(uint32_t worker_index, const Network::Socket& socket) {
#if defined(__linux__)
  if (socket_map_fd_ == INVALID_SOCKET) {
    return;
  }
  uint64_t key = worker_index;
  os_fd_t fd = socket.ioHandle().fdDoNotUse();
  if (bpf_map_update_elem(socket_map_fd_, &key, &fd, BPF_ANY) < 0) {
    ENVOY_LOG_MISC(error, "epoch_stable: registerWorkerSocket worker={} fd={} failed: {}",
                   worker_index, fd, errorDetails(errno));
    return;
  }

  uint32_t registered = registered_workers_.fetch_add(1) + 1;
  if (registered == concurrency_) {
    uint32_t zero = 0;
    bpf_map_update_elem(concurrency_fd_, &zero, &concurrency_, BPF_ANY);
    ENVOY_LOG_MISC(debug, "epoch_stable: all {} workers registered, concurrency set", concurrency_);
  }
#else
  UNREFERENCED_PARAMETER(worker_index);
  UNREFERENCED_PARAMETER(socket);
#endif
}

QuicConnectionIdWorkerSelector Factory::getCompatibleConnectionIdWorkerSelector(uint32_t) {
  // TODO(filipcacky): take from deterministic?
  return [](const Buffer::Instance&, uint32_t default_value) { return default_value; };
}

QuicConnectionIdObserverPtr Factory::createConnectionIdObserver() {
#if defined(__linux__)
  if (socket_map_fd_ == INVALID_SOCKET) {
    return nullptr;
  }
  return std::make_unique<EpochStableConnectionIdObserver>(socket_map_fd_, concurrency_);
#else
  return nullptr;
#endif
}

} // namespace EpochStable
} // namespace ConnectionIdGenerator
} // namespace Extensions
} // namespace Quic
} // namespace Envoy
