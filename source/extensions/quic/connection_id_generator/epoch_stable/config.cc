#include "source/extensions/quic/connection_id_generator/epoch_stable/config.h"

#include "envoy/common/exception.h"
#include "envoy/extensions/quic/connection_id_generator/epoch_stable/v3/epoch_stable.pb.h"
#include "envoy/extensions/quic/connection_id_generator/epoch_stable/v3/epoch_stable.pb.validate.h"

#include "source/extensions/quic/connection_id_generator/epoch_stable/epoch_stable.h"
#include "source/extensions/quic/connection_id_generator/epoch_stable/routing_config.h"

namespace Envoy {
namespace Quic {
namespace Extensions {
namespace ConnectionIdGenerator {
namespace EpochStable {

ProtobufTypes::MessagePtr ConfigFactory::createEmptyConfigProto() {
  return std::make_unique<
      envoy::extensions::quic::connection_id_generator::epoch_stable::v3::Config>();
}

EnvoyQuicConnectionIdGeneratorFactoryPtr
ConfigFactory::createQuicConnectionIdGeneratorFactory(const Protobuf::Message&,
                                                      ProtobufMessage::ValidationVisitor&,
                                                      Server::Configuration::FactoryContext&) {
  throwEnvoyExceptionOrPanic("envoy.quic.connection_id_generator.epoch_stable requires "
                             "envoy.restart_features.defer_worker_routing_init to be enabled");
}

absl::StatusOr<EnvoyQuicConnectionIdGeneratorFactoryPtr>
ConfigFactory::createQuicConnectionIdGeneratorFactoryForReuseportGroup(
    const Protobuf::Message& proto_message, Server::Configuration::FactoryContext& context,
    Network::ListenSocketFactory& listen_socket_factory) {
  MessageUtil::downcastAndValidate<
      const envoy::extensions::quic::connection_id_generator::epoch_stable::v3::Config&>(
      proto_message, context.messageValidationVisitor());

  const uint32_t concurrency = context.serverFactoryContext().options().concurrency();
  if (concurrency > EPOCH_STABLE_MAX_WORKERS) {
    return absl::InvalidArgumentError(fmt::format(
        "epoch_stable supports at most {} workers, got {}", EPOCH_STABLE_MAX_WORKERS, concurrency));
  }

  return std::make_unique<Factory>(listen_socket_factory);
}

REGISTER_FACTORY(ConfigFactory, EnvoyQuicConnectionIdGeneratorConfigFactory);

} // namespace EpochStable
} // namespace ConnectionIdGenerator
} // namespace Extensions
} // namespace Quic
} // namespace Envoy
