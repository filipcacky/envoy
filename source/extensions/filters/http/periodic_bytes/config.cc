#include "source/extensions/filters/http/periodic_bytes/config.h"

#include "envoy/registry/registry.h"

#include "source/common/protobuf/utility.h"
#include "source/extensions/filters/http/periodic_bytes/filter.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace PeriodicBytes {

Http::FilterFactoryCb PeriodicBytesFilterConfig::createFilterFactoryFromProtoTyped(
    const envoy::extensions::filters::http::periodic_bytes::v3::PeriodicBytes& proto_config,
    const std::string&, Server::Configuration::FactoryContext&) {
  const auto interval = std::chrono::milliseconds(
      DurationUtil::durationToMilliseconds(proto_config.interval()));
  const uint32_t response_bytes = proto_config.response_bytes();

  return [interval, response_bytes](Http::FilterChainFactoryCallbacks& callbacks) -> void {
    callbacks.addStreamDecoderFilter(
        std::make_shared<PeriodicBytesFilter>(interval, response_bytes));
  };
}

LEGACY_REGISTER_FACTORY(PeriodicBytesFilterConfig,
                        Server::Configuration::NamedHttpFilterConfigFactory,
                        "envoy.periodic_bytes");

} // namespace PeriodicBytes
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
