#pragma once

#include <deque>

#include "envoy/admin/v3/clusters.pb.h"
#include "envoy/buffer/buffer.h"
#include "envoy/http/codes.h"
#include "envoy/http/header_map.h"
#include "envoy/server/admin.h"
#include "envoy/server/instance.h"

#include "source/common/buffer/buffer_impl.h"
#include "source/server/admin/handler_ctx.h"

#include "re2/re2.h"

namespace Envoy {
namespace Server {

/**
 * A utility to set admin health status from a specified host and health flag.
 *
 * @param healthFlag    The specific health status to be checked.
 * @param host          The target host.
 * @param health_status A proto reference representing the admin health status.
 */
void setHealthFlag(Upstream::Host::HealthFlag flag, const Upstream::Host& host,
                   envoy::admin::v3::HostHealthStatus& health_status);

class ClustersHandler : public HandlerContextBase {

public:
  ClustersHandler(Server::Instance& server);

  Http::Code handlerClusters(Http::ResponseHeaderMap& response_headers, Buffer::Instance& response,
                             AdminStream&);

  Admin::UrlHandler handlerClustersStreamed();

  Admin::RequestPtr makeRequest(AdminStream& admin_stream);

private:
  void writeClustersAsJson(const std::optional<const re2::RE2>& filter, Buffer::Instance& response);
  void writeClustersAsText(const std::optional<const re2::RE2>& filter, Buffer::Instance& response);
};

class ClustersDumpRequest : public Admin::Request {
public:
  static constexpr uint64_t DefaultChunkSize = 2 * 1000 * 1000;

  ClustersDumpRequest(Server::Instance& server, std::deque<std::string> cluster_names);

  // Admin::Request
  bool nextChunk(Buffer::Instance& response) override;

  void setChunkSize(uint64_t chunk_size) { chunk_size_ = chunk_size; }

protected:
  OptRef<const Upstream::Cluster> nextCluster();

  Buffer::OwnedImpl response_;

private:
  virtual bool serializeNext() PURE;

  Server::Instance& server_;
  std::deque<std::string> cluster_names_;
  uint64_t chunk_size_{DefaultChunkSize};
};

class TextClustersDumpRequest : public ClustersDumpRequest {
public:
  using ClustersDumpRequest::ClustersDumpRequest;

  // Admin::Request
  Http::Code start(Http::ResponseHeaderMap& response_headers) override;

private:
  bool serializeNext() override;
};

class JsonClustersDumpRequest : public ClustersDumpRequest {
public:
  using ClustersDumpRequest::ClustersDumpRequest;
  ~JsonClustersDumpRequest() override;

  // Admin::Request
  Http::Code start(Http::ResponseHeaderMap& response_headers) override;

private:
  class Document;

  bool serializeNext() override;

  std::unique_ptr<Document> document_;
};

} // namespace Server
} // namespace Envoy
