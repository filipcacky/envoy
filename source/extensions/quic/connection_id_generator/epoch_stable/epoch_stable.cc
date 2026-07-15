#include "source/extensions/quic/connection_id_generator/epoch_stable/epoch_stable.h"

#include "envoy/common/exception.h"

#include "source/common/common/cleanup.h"
#include "source/common/network/bpf_syscalls.h"
#include "source/common/network/socket_option_impl.h"
#include "source/extensions/quic/connection_id_generator/epoch_stable/routing_config.h"

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

#ifdef ENVOY_EBPF_SUPPORTED
#include "source/extensions/quic/connection_id_generator/epoch_stable/route_bpf_embedded.h"
#endif

absl::Span<const uint8_t> routeBpfProgramData() {
#ifdef ENVOY_EBPF_SUPPORTED
  return {route_bpf_data, route_bpf_data_len};
#else
  return {};
#endif
}

} // namespace

std::optional<quic::QuicConnectionId>
EnvoyDeterministicConnectionIdGenerator::GenerateNextConnectionId(
    const quic::QuicConnectionId& original) {
  auto new_cid = DeterministicConnectionIdGenerator::GenerateNextConnectionId(original);
  if (!new_cid.has_value()) {
    return std::nullopt;
  }
  adjustNewConnectionIdForRouting(new_cid.value(), original);
  if (new_cid.value() == original) {
    return std::nullopt;
  }
  new_cid->mutable_data()[kGenByteOffset] = static_cast<char>(generation_);
  new_cid->mutable_data()[kWorkerIndexOffset] = static_cast<char>(worker_index_);
  return new_cid;
}

std::optional<quic::QuicConnectionId>
EnvoyDeterministicConnectionIdGenerator::MaybeReplaceConnectionId(
    const quic::QuicConnectionId& original, const quic::ParsedQuicVersion& version) {
  auto new_cid = DeterministicConnectionIdGenerator::MaybeReplaceConnectionId(original, version);
  if (!new_cid.has_value()) {
    return std::nullopt;
  }
  adjustNewConnectionIdForRouting(new_cid.value(), original);
  if (new_cid.value() == original) {
    return std::nullopt;
  }
  new_cid->mutable_data()[kGenByteOffset] = static_cast<char>(generation_);
  new_cid->mutable_data()[kWorkerIndexOffset] = static_cast<char>(worker_index_);
  return new_cid;
}

// Userspace equivalent of the routing performed by the eBPF program in route.c.
QuicConnectionIdWorkerSelector
Factory::getCompatibleConnectionIdWorkerSelector(uint32_t concurrency) {
  return [concurrency](const Buffer::Instance& packet, uint32_t default_value) -> uint32_t {
    uint8_t first_octet;
    if (packet.length() < sizeof(first_octet)) {
      return default_value;
    }
    packet.copyOut(0, sizeof(first_octet), &first_octet);

    if (first_octet & 0x80) {
      // Long header: flags(1) | version(4) | dcid_len(1) | dcid. New connections are routed by
      // the stable part of the connection ID.
      uint32_t stable_dcid_part;
      if (packet.length() < 6 + sizeof(stable_dcid_part)) {
        return default_value;
      }
      uint8_t dcid_len;
      packet.copyOut(5, sizeof(dcid_len), &dcid_len);
      if (dcid_len < quic::kQuicDefaultConnectionIdLength) {
        return default_value;
      }
      packet.copyOut(6, sizeof(stable_dcid_part), &stable_dcid_part);
      return stable_dcid_part % concurrency;
    }

    // Short header: flags(1) | dcid. Established connections carry the worker index directly in
    // the connection ID.
    uint8_t worker_index;
    if (packet.length() < 1 + kCidLength) {
      return default_value;
    }
    packet.copyOut(1 + kWorkerIndexOffset, sizeof(worker_index), &worker_index);
    return worker_index < concurrency ? worker_index : default_value;
  };
}

Factory::Factory(Network::ListenSocketFactory& listen_socket_factory)
    : listen_socket_factory_(listen_socket_factory) {}

absl::Status Factory::initialize() {
  program_ = listen_socket_factory_.reuseportEbpfProgram();
  const bool inherited = program_ != nullptr;
  if (!inherited) {
    RETURN_IF_NOT_OK(loadBpfProgram());
  }

  RETURN_IF_NOT_OK(loadMaps());

  if (inherited) {
    routing_config current{};
    uint32_t zero = 0;
    const auto lookup_result =
        Network::BpfSysCallsSingleton::get().bpfMapLookupElem(routing_fd_.fd(), &zero, &current);
    if (lookup_result.return_value_ < 0) {
      return absl::InternalError(
          fmt::format("routing_info not found: {}", errorDetails(lookup_result.errno_)));
    }
    current_generation_ = (current.generation + 1) % num_generations_;
    return absl::OkStatus();
  }

  RETURN_IF_NOT_OK(createGenerationMaps());
  // Publish the program so a hot restart child can inherit it.
  listen_socket_factory_.setReuseportEbpfProgram(program_);
  return absl::OkStatus();
}

absl::Status Factory::loadMaps() {
  auto& bpf = Network::BpfSysCallsSingleton::get();

  std::array<uint32_t, 16> map_ids{};
  uint32_t map_count = map_ids.size();
  const auto info_result = bpf.bpfProgGetMapIds(program_->fd(), absl::MakeSpan(map_ids), map_count);
  if (info_result.return_value_ < 0) {
    return absl::InternalError(
        fmt::format("failed to query program: {}", errorDetails(info_result.errno_)));
  }

  for (uint32_t i = 0; i < map_count; i++) {
    const auto map_fd_result = bpf.bpfMapGetFdById(map_ids[i]);
    if (!SOCKET_VALID(map_fd_result.return_value_)) {
      return absl::InternalError(fmt::format("failed to open map id {}: {}", map_ids[i],
                                             errorDetails(map_fd_result.errno_)));
    }
    // Closes the fd unless it is claimed by one of the members below.
    ScopedFd map_fd(map_fd_result.return_value_);

    Network::BpfMapInfo map_info;
    const auto map_info_result = bpf.bpfMapGetInfoByFd(map_fd.fd(), map_info);
    if (map_info_result.return_value_ < 0) {
      return absl::InternalError(
          fmt::format("failed to query map info: {}", errorDetails(map_info_result.errno_)));
    }

    if (map_info.name_ == "generations") {
      generations_fd_ = std::move(map_fd);
      num_generations_ = map_info.max_entries_;
    } else if (map_info.name_ == "routing") {
      routing_fd_ = std::move(map_fd);
    }
  }

  if (!generations_fd_.isValid() || !routing_fd_.isValid()) {
    return absl::InternalError("program missing required maps");
  }
  if (num_generations_ == 0) {
    return absl::InternalError("generations map has zero max_entries");
  }

  return absl::OkStatus();
}

absl::Status Factory::loadBpfProgram() {
  auto& bpf = Network::BpfSysCallsSingleton::get();

  const auto data = routeBpfProgramData();
  const auto open_result = bpf.bpfObjectOpenMem(data.data(), data.size());
  if (open_result.return_value_ == nullptr) {
    if (open_result.errno_ == ENOTSUP) {
      return absl::UnimplementedError(
          "envoy.quic.connection_id_generator.epoch_stable not available");
    }
    return absl::InternalError(
        fmt::format("failed to open bpf object: {}", errorDetails(open_result.errno_)));
  }
  auto* object = static_cast<bpf_object*>(open_result.return_value_);
  // The object and the fds it owns are released on all paths, the loaded program and its maps
  // are kept alive by the duplicated program fd.
  Cleanup close_object([&bpf, object]() { bpf.bpfObjectClose(object); });

  const auto load_result = bpf.bpfObjectLoad(object);
  if (load_result.return_value_ < 0) {
    return absl::InternalError(
        fmt::format("failed to load bpf object: {}", errorDetails(load_result.errno_)));
  }

  bpf_program* program = bpf.bpfObjectFindProgramByName(object, "epoch_stable_select_socket");
  if (program == nullptr) {
    return absl::InternalError("epoch_stable_select_socket not found");
  }
  const auto program_fd = bpf.bpfProgramFd(program);
  if (!SOCKET_VALID(program_fd.return_value_)) {
    return absl::InternalError(
        fmt::format("failed to get program fd: {}", errorDetails(program_fd.errno_)));
  }
  program_ = std::make_shared<ScopedFd>(::dup(program_fd.return_value_));
  if (!SOCKET_VALID(program_->fd())) {
    return absl::InternalError(
        fmt::format("failed to duplicate program fd: {}", errorDetails(errno)));
  }

  return absl::OkStatus();
}

absl::Status Factory::createGenerationMaps() {
  auto& bpf = Network::BpfSysCallsSingleton::get();

  for (uint32_t i = 0; i < num_generations_; ++i) {
    const auto name = fmt::format("generation_{}", i);
    const auto create_result =
        bpf.bpfMapCreateReuseportSockArray(EPOCH_STABLE_MAX_WORKERS, name.c_str());
    if (!SOCKET_VALID(create_result.return_value_)) {
      return absl::InternalError(
          fmt::format("failed to create inner map {}: {}", i, errorDetails(create_result.errno_)));
    }
    const ScopedFd inner_fd(create_result.return_value_);
    const uint32_t inner_map_fd = inner_fd.fd();
    const auto insert_result = bpf.bpfMapUpdateElem(generations_fd_.fd(), &i, &inner_map_fd);
    if (insert_result.return_value_ < 0) {
      return absl::InternalError(
          fmt::format("failed to insert inner map {}: {}", i, errorDetails(insert_result.errno_)));
    }
  }

  return absl::OkStatus();
}

QuicConnectionIdGeneratorPtr Factory::createQuicConnectionIdGenerator(uint32_t worker_index) {
  return std::make_unique<EnvoyDeterministicConnectionIdGenerator>(kCidLength, current_generation_,
                                                                   worker_index);
}

absl::StatusOr<Network::Socket::OptionConstSharedPtr>
Factory::createCompatibleLinuxBpfSocketOption(uint32_t concurrency) {
  concurrency_ = concurrency;
  RETURN_IF_NOT_OK(initialize());
  ASSERT(program_ != nullptr);
  return std::make_shared<Network::SocketOptionImpl>(
      envoy::config::core::v3::SocketOption::STATE_BOUND, ENVOY_ATTACH_REUSEPORT_EBPF,
      static_cast<int>(program_->fd()));
}

absl::Status Factory::registerWorkerSocket(uint32_t worker_index, const Network::Socket& socket) {
  if (!generations_fd_.isValid()) {
    // Kernel BPF packet routing is unavailable or disabled.
    return absl::OkStatus();
  }
  auto& bpf = Network::BpfSysCallsSingleton::get();

  uint32_t inner_id = 0;
  const uint32_t slot = current_generation_;
  const auto lookup_result = bpf.bpfMapLookupElem(generations_fd_.fd(), &slot, &inner_id);
  if (lookup_result.return_value_ < 0) {
    return absl::InternalError(fmt::format("getting id of generation {} failed: {}", slot,
                                           errorDetails(lookup_result.errno_)));
  }
  const auto inner_fd_result = bpf.bpfMapGetFdById(inner_id);
  const ScopedFd inner_fd(inner_fd_result.return_value_);
  if (!inner_fd.isValid()) {
    return absl::InternalError(fmt::format("getting fd of generation at id {} failed: {}", inner_id,
                                           errorDetails(inner_fd_result.errno_)));
  }

  const uint32_t sock_fd = socket.ioHandle().fdDoNotUse();
  const auto update_result = bpf.bpfMapUpdateElem(inner_fd.fd(), &worker_index, &sock_fd);
  if (update_result.return_value_ < 0) {
    return absl::InternalError(fmt::format("registering worker {} socket failed: {}", worker_index,
                                           errorDetails(update_result.errno_)));
  }

  if (++registered_workers_ == concurrency_) {
    routing_config cfg{};
    cfg.generation = current_generation_;
    cfg.concurrency = concurrency_;
    uint32_t zero = 0;
    const auto publish_result = bpf.bpfMapUpdateElem(routing_fd_.fd(), &zero, &cfg);
    if (publish_result.return_value_ < 0) {
      return absl::InternalError(
          fmt::format("publishing routing_config failed: {}", errorDetails(publish_result.errno_)));
    }
  }

  return absl::OkStatus();
}

} // namespace EpochStable
} // namespace ConnectionIdGenerator
} // namespace Extensions
} // namespace Quic
} // namespace Envoy
