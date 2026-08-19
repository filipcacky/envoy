#include <map>

#include "envoy/config/core/v3/base.pb.h"
#include "envoy/config/endpoint/v3/endpoint_components.pb.h"

#include "source/common/buffer/buffer_impl.h"
#include "source/common/common/macros.h"
#include "source/common/event/libevent.h"
#include "source/common/http/header_map_impl.h"
#include "source/common/network/utility.h"
#include "source/common/upstream/upstream_impl.h"
#include "source/server/admin/clusters_handler.h"

#include "test/benchmark/main.h"
#include "test/mocks/server/admin_stream.h"
#include "test/mocks/server/instance.h"
#include "test/mocks/upstream/cluster_info.h"
#include "test/mocks/upstream/cluster_manager.h"
#include "test/mocks/upstream/cluster_priority_set.h"
#include "test/mocks/upstream/host.h"

#include "benchmark/benchmark.h"

namespace Envoy {
namespace Server {

namespace {

constexpr uint32_t HostsPerCluster = 5;

class SharedHosts {
public:
  SharedHosts() {
    envoy::config::core::v3::Locality locality;
    locality.set_region("us-east");
    locality.set_zone("us-east-1a");
    locality.set_sub_zone("rack-1");
    auto shared_locality = std::make_shared<const envoy::config::core::v3::Locality>(locality);
    for (uint32_t i = 0; i < HostsPerCluster; i++) {
      hosts_.push_back(std::shared_ptr<Upstream::HostImpl>(*Upstream::HostImpl::create(
          info_, absl::StrCat("host-", i, ".example.com"),
          *Network::Utility::resolveUrl(absl::StrCat("tcp://10.0.0.", i + 1, ":8080")), nullptr,
          nullptr, 1, shared_locality,
          envoy::config::endpoint::v3::Endpoint::HealthCheckConfig::default_instance(), 0,
          envoy::config::core::v3::HEALTHY)));
    }
  }

  const std::vector<Upstream::HostSharedPtr>& hosts() const { return hosts_; }

private:
  std::shared_ptr<testing::NiceMock<Upstream::MockClusterInfo>> info_{
      std::make_shared<testing::NiceMock<Upstream::MockClusterInfo>>()};
  std::vector<Upstream::HostSharedPtr> hosts_;
};

using FakeCluster = testing::NiceMock<Upstream::MockClusterMockPrioritySet>;

// The clusters a benchmark dumps, held across benchmarks as the mocks are slow to build.
class ClusterSet {
public:
  explicit ClusterSet(uint32_t clusters) {
    ON_CALL(outlier_detector_, successRateAverage(testing::_)).WillByDefault(testing::Return(99.5));
    ON_CALL(outlier_detector_, successRateEjectionThreshold(testing::_))
        .WillByDefault(testing::Return(95.5));
    for (uint32_t i = 0; i < clusters; i++) {
      fake_clusters_.push_back(makeCluster(i));
      cluster_maps_.active_clusters_.emplace(fake_clusters_.back()->info_->name_,
                                             *fake_clusters_.back());
    }
  }

  const Upstream::ClusterManager::ClusterInfoMaps& clusterMaps() const { return cluster_maps_; }

private:
  std::unique_ptr<FakeCluster> makeCluster(uint32_t index) {
    auto cluster = std::make_unique<FakeCluster>();
    cluster->info_->name_ = absl::StrCat("cluster_", index);
    cluster->info_->observability_name_ = "observability_name";
    cluster->info_->eds_service_name_ = "eds_service_name";
    ON_CALL(*cluster->info_, addedViaApi()).WillByDefault(testing::Return(true));
    ON_CALL(testing::Const(*cluster), outlierDetector())
        .WillByDefault(testing::Return(&outlier_detector_));
    Upstream::MockHostSet* host_set = cluster->priority_set_.getMockHostSet(0);
    for (const Upstream::HostSharedPtr& host : hosts_.hosts()) {
      host_set->hosts_.emplace_back(host);
    }
    return cluster;
  }

  SharedHosts hosts_;
  testing::NiceMock<Upstream::Outlier::MockDetector> outlier_detector_;
  Upstream::ClusterManager::ClusterInfoMaps cluster_maps_;
  std::vector<std::unique_ptr<FakeCluster>> fake_clusters_;
};

using ClusterSetCache = std::map<uint32_t, std::unique_ptr<ClusterSet>>;

ClusterSetCache& clusterSetCache() { MUTABLE_CONSTRUCT_ON_FIRST_USE(ClusterSetCache); }

const ClusterSet& clusterSet(uint32_t clusters) {
  ClusterSetCache& cache = clusterSetCache();
  const auto cached = cache.find(clusters);
  if (cached != cache.end()) {
    return *cached->second;
  }
  benchmark::setCleanupHook([]() { clusterSetCache().clear(); });
  return *cache.emplace(clusters, std::make_unique<ClusterSet>(clusters)).first->second;
}

class ClustersSpeedTest {
public:
  ClustersSpeedTest(uint32_t clusters, absl::string_view format)
      : cluster_maps_(clusterSet(clusters).clusterMaps()) {
    Event::Libevent::Global::initialize();
    ON_CALL(server_.cluster_manager_, clusters())
        .WillByDefault(testing::ReturnPointee(&cluster_maps_));
    ON_CALL(server_.cluster_manager_, getActiveCluster(testing::_))
        .WillByDefault(
            testing::Invoke([this](absl::string_view name) -> OptRef<const Upstream::Cluster> {
              const auto it = cluster_maps_.active_clusters_.find(name);
              if (it == cluster_maps_.active_clusters_.end()) {
                return std::nullopt;
              }
              return it->second.get();
            }));

    if (!format.empty()) {
      query_params_.add("format", format);
    }
    ON_CALL(admin_stream_, queryParams()).WillByDefault(testing::Return(query_params_));
  }

  ClustersHandler& handler() { return handler_; }
  AdminStream& adminStream() { return admin_stream_; }

private:
  testing::NiceMock<MockInstance> server_;
  const Upstream::ClusterManager::ClusterInfoMaps& cluster_maps_;
  Http::Utility::QueryParamsMulti query_params_;
  ClustersHandler handler_{server_};
  testing::NiceMock<MockAdminStream> admin_stream_;
};

} // namespace
} // namespace Server
} // namespace Envoy

namespace {

uint32_t clusterCount(const benchmark::State& state) {
  const auto clusters = static_cast<uint32_t>(state.range(0));
  return Envoy::benchmark::skipExpensiveBenchmarks() ? std::min(clusters, 100U) : clusters;
}

void clusterSizes(benchmark::internal::Benchmark* benchmark) {
  benchmark->Arg(100)->Arg(1000)->Arg(10000)->Unit(benchmark::kMillisecond);
}

uint64_t run(benchmark::State& state, Envoy::Server::ClustersSpeedTest& test_context) {
  Envoy::Http::ResponseHeaderMapPtr headers = Envoy::Http::ResponseHeaderMapImpl::create();
  Envoy::Buffer::OwnedImpl chunk;
  uint64_t response_bytes = 0;
  for (auto _ : state) { // NOLINT
    Envoy::Server::Admin::RequestPtr request =
        test_context.handler().makeRequest(test_context.adminStream());
    request->start(*headers);

    for (bool more = true; more;) {
      more = request->nextChunk(chunk);

      state.PauseTiming();
      response_bytes += chunk.length();
      chunk.drain(chunk.length());
      state.ResumeTiming();
    }
  }
  return response_bytes;
}

// NOLINTNEXTLINE(readability-identifier-naming)
static void BM_Clusters(benchmark::State& state, absl::string_view format) {
  Envoy::Server::ClustersSpeedTest test_context(clusterCount(state), format);
  state.SetBytesProcessed(run(state, test_context));
}
BENCHMARK_CAPTURE(BM_Clusters, text, "")->Apply(clusterSizes);
BENCHMARK_CAPTURE(BM_Clusters, json, "json")->Apply(clusterSizes);

} // namespace
