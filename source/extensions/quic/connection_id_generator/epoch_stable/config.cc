#include "source/extensions/quic/connection_id_generator/epoch_stable/config.h"

#include "envoy/extensions/quic/connection_id_generator/epoch_stable/v3/epoch_stable.pb.h"
#include "envoy/extensions/quic/connection_id_generator/epoch_stable/v3/epoch_stable.pb.validate.h"

#include "source/extensions/quic/connection_id_generator/epoch_stable/epoch_stable.h"

#include "absl/strings/string_view.h"

#if defined(__linux__)
#include <linux/magic.h>
#include <sys/vfs.h>
#endif

namespace Envoy {
namespace Quic {
namespace Extensions {
namespace ConnectionIdGenerator {
namespace EpochStable {
namespace {

absl::Status validateBpfPinPath(Filesystem::Instance& fs, absl::string_view path) {
  auto split_or = fs.splitPathFromFilename(path);
  if (!split_or.ok()) {
    return absl::InvalidArgumentError(
        fmt::format("bpf_pin_path '{}': {}", path, split_or.status().message()));
  }

  std::string dir(split_or->directory_);
  if (!fs.directoryExists(dir)) {
    return absl::InvalidArgumentError(
        fmt::format("bpf_pin_path '{}': parent directory '{}' does not exist", path, dir));
  }

#if defined(__linux__)
  struct statfs st;
  if (statfs(dir.c_str(), &st) != 0) {
    return absl::InvalidArgumentError(
        fmt::format("bpf_pin_path '{}': {}", path, errorDetails(errno)));
  }

  if (static_cast<unsigned long>(st.f_type) != BPF_FS_MAGIC) {
    return absl::InvalidArgumentError(
        fmt::format("bpf_pin_path '{}': '{}' is not on a BPF filesystem (type 0x{:x})."
                    " Mount with: mount -t bpf bpf /sys/fs/bpf",
                    path, dir, st.f_type));
  }
#endif

  return absl::OkStatus();
}

} // namespace

ProtobufTypes::MessagePtr ConfigFactory::createEmptyConfigProto() {
  return std::make_unique<
      envoy::extensions::quic::connection_id_generator::epoch_stable::v3::Config>();
}

EnvoyQuicConnectionIdGeneratorFactoryPtr ConfigFactory::createQuicConnectionIdGeneratorFactory(
    const Protobuf::Message& config, ProtobufMessage::ValidationVisitor& validation_visitor,
    Server::Configuration::FactoryContext& factory_context) {
  const auto& proto = MessageUtil::downcastAndValidate<
      const envoy::extensions::quic::connection_id_generator::epoch_stable::v3::Config&>(
      config, validation_visitor);

  const auto bpf_pin_path = PROTOBUF_GET_WRAPPED_REQUIRED(proto, bpf_pin_path);
  auto directory_status =
      validateBpfPinPath(factory_context.serverFactoryContext().api().fileSystem(), bpf_pin_path);
  THROW_IF_NOT_OK_REF(directory_status);

  EpochStableConfig epoch_config(PROTOBUF_GET_WRAPPED_OR_DEFAULT(proto, max_map_entries, 65536),
                                 bpf_pin_path);

  auto factory_or_status = Factory::create(epoch_config);
  THROW_IF_NOT_OK_REF(factory_or_status.status());
  return std::move(factory_or_status.value());
}

REGISTER_FACTORY(ConfigFactory, EnvoyQuicConnectionIdGeneratorConfigFactory);

} // namespace EpochStable
} // namespace ConnectionIdGenerator
} // namespace Extensions
} // namespace Quic
} // namespace Envoy
