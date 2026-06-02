#include "source/extensions/quic/connection_id_generator/epoch_stable/epoch_stable.h"

#include "source/common/network/socket_option_impl.h"

#if defined(__linux__)
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <sys/stat.h>

#include "source/extensions/quic/connection_id_generator/epoch_stable/route_bpf_embedded.h"
#include "source/extensions/quic/connection_id_generator/epoch_stable/routing_config.h"
#endif

namespace Envoy {
namespace Quic {
namespace Extensions {
namespace ConnectionIdGenerator {
namespace EpochStable {
namespace {

constexpr size_t kGenByteOffset = quic::kQuicDefaultConnectionIdLength;
constexpr size_t kWorkerIndexOffset = quic::kQuicDefaultConnectionIdLength + 1;
constexpr uint32_t kCidLength = quic::kQuicDefaultConnectionIdLength + 2;

void adjustNewConnectionIdForRouting(quic::QuicConnectionId& new_connection_id,
                                     const quic::QuicConnectionId& old_connection_id) {
  char* new_connection_id_data = new_connection_id.mutable_data();
  const char* old_connection_id_ptr = old_connection_id.data();
  memcpy(new_connection_id_data, old_connection_id_ptr, 4); // NOLINT(safe-memcpy)
}

} // namespace

absl::optional<quic::QuicConnectionId>
EnvoyDeterministicConnectionIdGenerator::GenerateNextConnectionId(
    const quic::QuicConnectionId& original) {
  auto new_cid = DeterministicConnectionIdGenerator::GenerateNextConnectionId(original);
  if (!new_cid.has_value()) {
    return absl::nullopt;
  }
  adjustNewConnectionIdForRouting(new_cid.value(), original);
  if (new_cid.value() == original) {
    return absl::nullopt;
  }
  new_cid->mutable_data()[kGenByteOffset] = static_cast<char>(generation_);
  new_cid->mutable_data()[kWorkerIndexOffset] = static_cast<char>(worker_index_);
  return new_cid;
}

absl::optional<quic::QuicConnectionId>
EnvoyDeterministicConnectionIdGenerator::MaybeReplaceConnectionId(
    const quic::QuicConnectionId& original, const quic::ParsedQuicVersion& version) {
  auto new_cid = DeterministicConnectionIdGenerator::MaybeReplaceConnectionId(original, version);
  if (!new_cid.has_value()) {
    return absl::nullopt;
  }
  adjustNewConnectionIdForRouting(new_cid.value(), original);
  if (new_cid.value() == original) {
    return absl::nullopt;
  }
  new_cid->mutable_data()[kGenByteOffset] = static_cast<char>(generation_);
  new_cid->mutable_data()[kWorkerIndexOffset] = static_cast<char>(worker_index_);
  return new_cid;
}

Factory::Factory(const EpochStableConfig& config) : config_(config) {}

Factory::~Factory() {
#if defined(__linux__)
  if (SOCKET_VALID(generations_fd_)) {
    close(generations_fd_);
  }
  if (SOCKET_VALID(routing_fd_)) {
    close(routing_fd_);
  }
  if (SOCKET_VALID(prog_fd_)) {
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
  std::array<uint32_t, 16> map_ids{};
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
      return cleanupAndError(fmt::format("failed to query map info: {}", errorDetails(errno)));
    }

    if (strcmp(map_info.name, "generations") == 0) {
      generations_fd_ = map_fd;
      num_generations_ = map_info.max_entries;
    } else if (strcmp(map_info.name, "routing") == 0) {
      routing_fd_ = map_fd;
    } else {
      close(map_fd);
    }
  }

  if (generations_fd_ < 0 || routing_fd_ < 0) {
    return cleanupAndError("program missing required maps");
  }
  if (num_generations_ == 0) {
    return cleanupAndError("generations map has zero max_entries");
  }

  return absl::OkStatus();
#else
  UNREFERENCED_PARAMETER(prog_fd);
  return absl::UnimplementedError(
      "envoy.quic.epoch_stable_routing_connection_id_generator not available");
#endif
}

QuicConnectionIdGeneratorPtr Factory::createQuicConnectionIdGenerator(uint32_t worker_index) {
  return std::make_unique<EnvoyDeterministicConnectionIdGenerator>(kCidLength, current_generation_,
                                                                   worker_index);
}

absl::StatusOr<Network::Socket::OptionConstSharedPtr>
Factory::createCompatibleLinuxBpfSocketOption(uint32_t concurrency, os_fd_t prog_fd) {
#if defined(SO_ATTACH_REUSEPORT_EBPF) && defined(__linux__)
  concurrency_ = concurrency;

  if (prog_fd != INVALID_SOCKET) {
    prog_fd_ = prog_fd;
    RETURN_IF_NOT_OK(loadMaps(prog_fd_));

    routing_config current{};
    uint32_t zero = 0;
    if (bpf_map_lookup_elem(routing_fd_, &zero, &current) < 0) {
      return cleanupAndError(fmt::format("routing_info not found: {}", errorDetails(errno)));
    }

    current_generation_ = (current.generation + 1) % num_generations_;
    return nullptr;
  }

  RETURN_IF_NOT_OK(loadBpfProgram());

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
    return absl::InternalError(fmt::format("failed to open bpf object: {}", errorDetails(errno)));
  }

  struct bpf_map* reuseport_proto = bpf_object__find_map_by_name(bpf_obj, "reuseport_map");
  if (reuseport_proto == nullptr) {
    return cleanupAndError("reuseport_map prototype not found in BPF object");
  }
  const auto inner_map_max_entries = bpf_map__max_entries(reuseport_proto);

  if (bpf_object__load(bpf_obj) < 0) {
    return cleanupAndError(fmt::format("failed to load bpf object: {}", errorDetails(errno)));
  }

  struct bpf_program* prog =
      bpf_object__find_program_by_name(bpf_obj, "epoch_stable_select_socket");
  if (prog == nullptr) {
    return cleanupAndError("epoch_stable_select_socket not found");
  }

  prog_fd_ = bpf_program__fd(prog);
  if (prog_fd_ < 0) {
    return cleanupAndError(fmt::format("failed to get program fd: {}", errorDetails(errno)));
  }

  generations_fd_ = bpf_map__fd(bpf_object__find_map_by_name(bpf_obj, "generations"));
  if (generations_fd_ < 0) {
    return cleanupAndError(fmt::format("failed to get generations fd: {}", errorDetails(errno)));
  }
  routing_fd_ = bpf_map__fd(bpf_object__find_map_by_name(bpf_obj, "routing"));
  if (routing_fd_ < 0) {
    return cleanupAndError(fmt::format("failed to get routing fd: {}", errorDetails(errno)));
  }

  bpf_map_info gen_info{};
  __u32 gen_info_len = sizeof(gen_info);
  if (bpf_map_get_info_by_fd(generations_fd_, &gen_info, &gen_info_len) < 0) {
    return cleanupAndError(
        fmt::format("failed to query generations map info: {}", errorDetails(errno)));
  }
  num_generations_ = gen_info.max_entries;
  if (num_generations_ == 0) {
    return cleanupAndError("generations map has zero max_entries");
  }

  bpf_map_create_opts inner_opts{};
  inner_opts.sz = sizeof(inner_opts);
  for (uint32_t i = 0; i < num_generations_; ++i) {
    const auto name = fmt::format("generation_{}", i);
    const int inner_fd =
        bpf_map_create(BPF_MAP_TYPE_REUSEPORT_SOCKARRAY, name.c_str(), sizeof(uint32_t),
                       sizeof(uint32_t), inner_map_max_entries, &inner_opts);
    if (inner_fd < 0) {
      return cleanupAndError(
          fmt::format("failed to create inner map {}: {}", i, errorDetails(errno)));
    }
    const int rc = bpf_map_update_elem(generations_fd_, &i, &inner_fd, BPF_ANY);
    const int saved_errno = errno;
    close(inner_fd);
    if (rc < 0) {
      return cleanupAndError(
          fmt::format("failed to insert inner map {}: {}", i, errorDetails(saved_errno)));
    }
  }

  return absl::OkStatus();
#else
  return absl::UnavailableError("eBPF not supported");
#endif
}

absl::Status Factory::cleanupAndError(absl::string_view message) {
#if defined(__linux__)
  if (SOCKET_VALID(generations_fd_)) {
    close(generations_fd_);
    generations_fd_ = INVALID_SOCKET;
  }
  if (SOCKET_VALID(routing_fd_)) {
    close(routing_fd_);
    routing_fd_ = INVALID_SOCKET;
  }
  if (SOCKET_VALID(prog_fd_)) {
    close(prog_fd_);
    prog_fd_ = INVALID_SOCKET;
  }
  return absl::InternalError(message);
#else
  UNREFERENCED_PARAMETER(message);
  return absl::OkStatus();
#endif
}

void Factory::registerWorkerSocket(uint32_t worker_index, const Network::Socket& socket) {
#if defined(__linux__)
  const os_fd_t sock_fd = socket.ioHandle().fdDoNotUse();

  uint32_t inner_id = 0;
  const uint32_t slot = static_cast<uint32_t>(current_generation_);
  if (bpf_map_lookup_elem(generations_fd_, &slot, &inner_id) < 0) {
    ENVOY_LOG_MISC(error, "getting id of generation {} failed: {}", slot, errorDetails(errno));
    return;
  }
  const int inner_fd = bpf_map_get_fd_by_id(inner_id);
  if (inner_fd < 0) {
    ENVOY_LOG_MISC(error, "getting fd of current generation at id {} failed: {}", inner_id,
                   errorDetails(errno));
    return;
  }

  const int rc = bpf_map_update_elem(inner_fd, &worker_index, &sock_fd, BPF_ANY);
  const int saved_errno = errno;
  close(inner_fd);

  if (rc < 0) {
    ENVOY_LOG_MISC(error, "registerWorkerSocket gen={} worker={} fd={} failed: {}",
                   current_generation_, worker_index, sock_fd, errorDetails(saved_errno));
    return;
  }

  if (registered_workers_.fetch_add(1) + 1 == concurrency_) {
    routing_config cfg{};
    cfg.generation = static_cast<uint8_t>(current_generation_);
    cfg.concurrency = concurrency_;
    uint32_t zero = 0;
    if (bpf_map_update_elem(routing_fd_, &zero, &cfg, BPF_ANY) < 0) {
      ENVOY_LOG_MISC(error, "publishing routing_config failed: {}", errorDetails(errno));
    }
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

} // namespace EpochStable
} // namespace ConnectionIdGenerator
} // namespace Extensions
} // namespace Quic
} // namespace Envoy
