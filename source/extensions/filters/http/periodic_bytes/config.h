#pragma once

#include "envoy/extensions/filters/http/periodic_bytes/v3/periodic_bytes.pb.h"
#include "envoy/extensions/filters/http/periodic_bytes/v3/periodic_bytes.pb.validate.h"

#include "source/extensions/filters/http/common/factory_base.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace PeriodicBytes {

class PeriodicBytesFilterConfig
    : public Common::FactoryBase<
          envoy::extensions::filters::http::periodic_bytes::v3::PeriodicBytes> {
public:
  PeriodicBytesFilterConfig() : FactoryBase("envoy.filters.http.periodic_bytes") {}

private:
  bool isTerminalFilterByProtoTyped(
      const envoy::extensions::filters::http::periodic_bytes::v3::PeriodicBytes&,
      Server::Configuration::ServerFactoryContext&) override {
    return true;
  }

  Http::FilterFactoryCb createFilterFactoryFromProtoTyped(
      const envoy::extensions::filters::http::periodic_bytes::v3::PeriodicBytes& proto_config,
      const std::string& stats_prefix, Server::Configuration::FactoryContext& context) override;
};

} // namespace PeriodicBytes
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
