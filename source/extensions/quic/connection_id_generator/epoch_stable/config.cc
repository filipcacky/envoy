#include "source/extensions/quic/connection_id_generator/epoch_stable/config.h"

#include "envoy/common/exception.h"
#include "envoy/extensions/quic/connection_id_generator/epoch_stable/v3/epoch_stable.pb.h"
#include "envoy/extensions/quic/connection_id_generator/epoch_stable/v3/epoch_stable.pb.validate.h"

#include "source/extensions/quic/connection_id_generator/epoch_stable/epoch_stable.h"

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
                                                      Server::Configuration::FactoryContext&) {
  return nullptr;
}

EnvoyQuicConnectionIdGeneratorFactoryPtr
ConfigFactory::createQuicConnectionIdGeneratorFactoryForReuseportGroup(
    const Protobuf::Message& proto_message, Server::Configuration::FactoryContext& context,
    Network::ListenSocketFactory& listen_socket_factory) {
  MessageUtil::downcastAndValidate<
      const envoy::extensions::quic::connection_id_generator::epoch_stable::v3::Config&>(
      proto_message, context.messageValidationVisitor());

  return std::make_unique<Factory>(context.serverFactoryContext().options().concurrency(),
                                   listen_socket_factory);
}

REGISTER_FACTORY(ConfigFactory, EnvoyQuicConnectionIdGeneratorConfigFactory);

} // namespace EpochStable
} // namespace ConnectionIdGenerator
} // namespace Extensions
} // namespace Quic
} // namespace Envoy
