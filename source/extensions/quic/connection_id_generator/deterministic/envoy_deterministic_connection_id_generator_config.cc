#include "source/extensions/quic/connection_id_generator/deterministic/envoy_deterministic_connection_id_generator_config.h"

#include "envoy/extensions/quic/connection_id_generator/v3/envoy_deterministic_connection_id_generator.pb.h"

#include "source/common/quic/envoy_deterministic_connection_id_generator.h"

namespace Envoy {
namespace Quic {
namespace Extensions {
namespace ConnectionIdGenerator {
namespace Deterministic {

ProtobufTypes::MessagePtr
EnvoyDeterministicConnectionIdGeneratorConfigFactory::createEmptyConfigProto() {
  return std::make_unique<envoy::extensions::quic::connection_id_generator::v3::
                              DeterministicConnectionIdGeneratorConfig>();
}

EnvoyQuicConnectionIdGeneratorFactoryPtr
EnvoyDeterministicConnectionIdGeneratorConfigFactory::createQuicConnectionIdGeneratorFactory(
    const Protobuf::Message&, Server::Configuration::FactoryContext& factory_context) {
  return std::make_unique<EnvoyDeterministicConnectionIdGeneratorFactory>(
      factory_context.serverFactoryContext().options().concurrency());
}

REGISTER_FACTORY(EnvoyDeterministicConnectionIdGeneratorConfigFactory,
                 EnvoyQuicConnectionIdGeneratorConfigFactory);

} // namespace Deterministic
} // namespace ConnectionIdGenerator
} // namespace Extensions
} // namespace Quic
} // namespace Envoy
