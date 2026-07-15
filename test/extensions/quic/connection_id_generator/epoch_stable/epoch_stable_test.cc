#include "source/common/buffer/buffer_impl.h"
#include "source/common/network/bpf_syscalls.h"
#include "source/extensions/quic/connection_id_generator/epoch_stable/epoch_stable.h"
#include "source/extensions/quic/connection_id_generator/epoch_stable/routing_config.h"

#include "test/mocks/network/mocks.h"
#include "test/test_common/status_utility.h"
#include "test/test_common/threadsafe_singleton_injector.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "quiche/quic/test_tools/quic_test_utils.h"

namespace Envoy {
namespace Quic {
namespace Extensions {
namespace ConnectionIdGenerator {
namespace EpochStable {
namespace {

using testing::_;
using testing::HasSubstr;
using testing::Invoke;
using testing::NiceMock;
using testing::Return;
using testing::SaveArg;
using testing::StrEq;

constexpr uint32_t kNumGenerations = 4;
constexpr uint32_t kConcurrency = 2;
constexpr os_fd_t kSocketFd = 43;
constexpr uint32_t kInnerMapId = 77;

class EpochStableFactoryTest : public testing::Test {
protected:
  EpochStableFactoryTest() {
    ON_CALL(listen_socket_factory_, getListenSocket(_)).WillByDefault(Return(listen_socket_));
    ON_CALL(static_cast<Network::MockIoHandle&>(listen_socket_->ioHandle()), fdDoNotUse())
        .WillByDefault(Return(kSocketFd));
  }

  ~EpochStableFactoryTest() override {
    // Some fds were transferred to the factory and are already closed.
    for (const os_fd_t fd : owned_fds_) {
      ::close(fd);
    }
  }

  // Creates a real fd (read end of a pipe) to stand in for bpf program and map fds.
  os_fd_t makeFd() {
    int fds[2];
    EXPECT_EQ(::pipe(fds), 0);
    ::close(fds[1]);
    owned_fds_.push_back(fds[0]);
    return fds[0];
  }

  // Wires prog-info map discovery with known generations/routing map fds. The queried program fd
  // is not matched, in the fresh-load path it is a duplicate with an unknown value.
  void expectMapDiscovery() {
    generations_fd_ = makeFd();
    routing_fd_ = makeFd();

    EXPECT_CALL(bpf_, bpfProgGetMapIds(_, _, _))
        .WillOnce(Invoke([](os_fd_t, absl::Span<uint32_t> map_ids, uint32_t& count) {
          map_ids[0] = 11;
          map_ids[1] = 12;
          count = 2;
          return Api::SysCallIntResult{0, 0};
        }));
    EXPECT_CALL(bpf_, bpfMapGetFdById(11))
        .WillOnce(Return(Api::SysCallSocketResult{generations_fd_, 0}));
    EXPECT_CALL(bpf_, bpfMapGetFdById(12))
        .WillOnce(Return(Api::SysCallSocketResult{routing_fd_, 0}));
    EXPECT_CALL(bpf_, bpfMapGetInfoByFd(generations_fd_, _))
        .WillOnce(Invoke([](os_fd_t, Network::BpfMapInfo& info) {
          info.name_ = "generations";
          info.max_entries_ = kNumGenerations;
          return Api::SysCallIntResult{0, 0};
        }));
    EXPECT_CALL(bpf_, bpfMapGetInfoByFd(routing_fd_, _))
        .WillOnce(Invoke([](os_fd_t, Network::BpfMapInfo& info) {
          info.name_ = "routing";
          info.max_entries_ = 1;
          return Api::SysCallIntResult{0, 0};
        }));
  }

  // Wires the mock syscalls for adopting an inherited program with known map fds.
  void expectInheritedMaps() {
    inherited_program_ = std::make_shared<ScopedFd>(makeFd());
    ON_CALL(listen_socket_factory_, reuseportEbpfProgram())
        .WillByDefault(Return(inherited_program_));
    EXPECT_CALL(listen_socket_factory_, setReuseportEbpfProgram(_)).Times(0);
    expectMapDiscovery();
  }

  // Initializes the factory with an inherited program whose routing map carries the given
  // previous generation.
  void initializeInherited(uint8_t previous_generation) {
    expectInheritedMaps();
    EXPECT_CALL(bpf_, bpfMapLookupElem(routing_fd_, _, _))
        .WillOnce(Invoke([previous_generation](os_fd_t, const void*, void* value) {
          auto* cfg = static_cast<routing_config*>(value);
          cfg->generation = previous_generation;
          cfg->concurrency = kConcurrency;
          return Api::SysCallIntResult{0, 0};
        }));
    ASSERT_OK(factory_.createCompatibleLinuxBpfSocketOption(kConcurrency));
  }

  // Expects worker socket registrations into the given generation's inner map, recording worker
  // updates and routing_config publications.
  void expectWorkerRegistration(uint32_t expected_generation, int times) {
    EXPECT_CALL(bpf_, bpfMapLookupElem(generations_fd_, _, _))
        .Times(times)
        .WillRepeatedly(Invoke([expected_generation](os_fd_t, const void* key, void* value) {
          EXPECT_EQ(*static_cast<const uint32_t*>(key), expected_generation);
          *static_cast<uint32_t*>(value) = kInnerMapId;
          return Api::SysCallIntResult{0, 0};
        }));
    EXPECT_CALL(bpf_, bpfMapGetFdById(kInnerMapId))
        .Times(times)
        .WillRepeatedly(Invoke([this](uint32_t) { return Api::SysCallSocketResult{makeFd(), 0}; }));
    EXPECT_CALL(bpf_, bpfMapUpdateElem(_, _, _))
        .WillRepeatedly(Invoke([this](os_fd_t fd, const void* key, const void* value) {
          if (fd == routing_fd_) {
            published_.push_back(*static_cast<const routing_config*>(value));
          } else {
            worker_updates_.emplace_back(*static_cast<const uint32_t*>(key),
                                         *static_cast<const uint32_t*>(value));
          }
          return Api::SysCallIntResult{0, 0};
        }));
  }

  std::vector<os_fd_t> owned_fds_;
  NiceMock<Network::MockBpfSysCalls> bpf_;
  TestThreadsafeSingletonInjector<Network::BpfSysCallsImpl> bpf_injector_{&bpf_};

  NiceMock<Network::MockListenSocketFactory> listen_socket_factory_;
  std::shared_ptr<NiceMock<Network::MockListenSocket>> listen_socket_{
      std::make_shared<NiceMock<Network::MockListenSocket>>()};

  ScopedFdSharedPtr inherited_program_;
  os_fd_t generations_fd_{INVALID_SOCKET};
  os_fd_t routing_fd_{INVALID_SOCKET};
  std::vector<std::pair<uint32_t, uint32_t>> worker_updates_;
  std::vector<routing_config> published_;

  Factory factory_{listen_socket_factory_};
};

TEST_F(EpochStableFactoryTest, LoadsProgramAndCreatesGenerationMaps) {
  auto* object = reinterpret_cast<bpf_object*>(0x1);
  auto* program = reinterpret_cast<bpf_program*>(0x2);

  EXPECT_CALL(bpf_, bpfObjectOpenMem(_, _)).WillOnce(Return(Api::SysCallPtrResult{object, 0}));
  EXPECT_CALL(bpf_, bpfObjectLoad(object)).WillOnce(Return(Api::SysCallIntResult{0, 0}));
  EXPECT_CALL(bpf_, bpfObjectFindProgramByName(object, StrEq("epoch_stable_select_socket")))
      .WillOnce(Return(program));
  EXPECT_CALL(bpf_, bpfProgramFd(program)).WillOnce(Return(Api::SysCallIntResult{makeFd(), 0}));
  EXPECT_CALL(bpf_, bpfObjectClose(object));
  expectMapDiscovery();

  for (uint32_t i = 0; i < kNumGenerations; ++i) {
    EXPECT_CALL(bpf_, bpfMapCreateReuseportSockArray(EPOCH_STABLE_MAX_WORKERS,
                                                     StrEq(fmt::format("generation_{}", i))))
        .WillOnce(Invoke(
            [this](uint32_t, const char*) { return Api::SysCallSocketResult{makeFd(), 0}; }));
  }
  std::vector<uint32_t> inserted_generations;
  EXPECT_CALL(bpf_, bpfMapUpdateElem(_, _, _))
      .Times(kNumGenerations)
      .WillRepeatedly(Invoke([&](os_fd_t fd, const void* key, const void*) {
        EXPECT_EQ(fd, generations_fd_);
        inserted_generations.push_back(*static_cast<const uint32_t*>(key));
        return Api::SysCallIntResult{0, 0};
      }));

  ScopedFdSharedPtr published_program;
  EXPECT_CALL(listen_socket_factory_, setReuseportEbpfProgram(_))
      .WillOnce(SaveArg<0>(&published_program));

  const auto option = factory_.createCompatibleLinuxBpfSocketOption(kConcurrency);
  ASSERT_OK(option);
  EXPECT_NE(*option, nullptr);
  ASSERT_NE(published_program, nullptr);
  EXPECT_TRUE(SOCKET_VALID(published_program->fd()));
  EXPECT_THAT(inserted_generations, testing::ElementsAre(0, 1, 2, 3));
}

TEST_F(EpochStableFactoryTest, LoadFailurePropagates) {
  EXPECT_CALL(bpf_, bpfObjectOpenMem(_, _))
      .WillOnce(Return(Api::SysCallPtrResult{nullptr, ENOTSUP}));

  const auto option = factory_.createCompatibleLinuxBpfSocketOption(kConcurrency);
  EXPECT_THAT(option, StatusHelpers::HasStatusCode(absl::StatusCode::kUnimplemented));
}

TEST_F(EpochStableFactoryTest, RoutingConfigLookupFailurePropagates) {
  expectInheritedMaps();
  EXPECT_CALL(bpf_, bpfMapLookupElem(routing_fd_, _, _))
      .WillOnce(Return(Api::SysCallIntResult{-1, ENOENT}));

  const auto option = factory_.createCompatibleLinuxBpfSocketOption(kConcurrency);
  EXPECT_THAT(option, StatusHelpers::HasStatusCode(absl::StatusCode::kInternal));
  EXPECT_THAT(option, StatusHelpers::HasStatusMessage(HasSubstr("routing_info not found")));
}

TEST_F(EpochStableFactoryTest, PublishesRoutingConfigAfterLastWorker) {
  initializeInherited(/*previous_generation=*/1);

  expectWorkerRegistration(/*expected_generation=*/2, /*times=*/kConcurrency);

  EXPECT_OK(factory_.registerWorkerSocket(0, *listen_socket_));
  EXPECT_EQ(worker_updates_.size(), 1u);
  EXPECT_TRUE(published_.empty()); // Only published once all workers have registered.

  EXPECT_OK(factory_.registerWorkerSocket(1, *listen_socket_));
  ASSERT_EQ(worker_updates_.size(), 2u);
  EXPECT_EQ(worker_updates_[0], std::make_pair(0u, static_cast<uint32_t>(kSocketFd)));
  EXPECT_EQ(worker_updates_[1], std::make_pair(1u, static_cast<uint32_t>(kSocketFd)));
  ASSERT_EQ(published_.size(), 1u);
  EXPECT_EQ(published_[0].generation, 2);
  EXPECT_EQ(published_[0].concurrency, kConcurrency);
}

TEST_F(EpochStableFactoryTest, WorkerRegistrationFailurePropagates) {
  initializeInherited(/*previous_generation=*/0);

  EXPECT_CALL(bpf_, bpfMapLookupElem(generations_fd_, _, _))
      .WillOnce(Return(Api::SysCallIntResult{-1, EIO}));

  const auto status = factory_.registerWorkerSocket(0, *listen_socket_);
  EXPECT_THAT(status, StatusHelpers::HasStatusCode(absl::StatusCode::kInternal));
  EXPECT_THAT(status, StatusHelpers::HasStatusMessage(HasSubstr("getting id of generation")));
}

class EpochStableFactoryGenerationTest
    : public EpochStableFactoryTest,
      public testing::WithParamInterface<std::tuple<uint8_t, uint8_t>> {};

INSTANTIATE_TEST_SUITE_P(Generations, EpochStableFactoryGenerationTest,
                         testing::Values(std::make_tuple(0, 1), std::make_tuple(2, 3),
                                         std::make_tuple(kNumGenerations - 1, 0)));

TEST_P(EpochStableFactoryGenerationTest, InheritedProgramBumpsGeneration) {
  const auto [previous_generation, expected_generation] = GetParam();

  initializeInherited(previous_generation);

  // The bumped generation is observable through worker socket registration.
  expectWorkerRegistration(expected_generation, /*times=*/1);
  EXPECT_OK(factory_.registerWorkerSocket(0, *listen_socket_));
  ASSERT_EQ(worker_updates_.size(), 1u);
}

TEST(EpochStableConnectionIdGeneratorTest, StampsGenerationAndWorkerIndex) {
  EnvoyDeterministicConnectionIdGenerator generator(/*connection_id_length=*/10,
                                                    /*generation=*/3, /*worker_index=*/7);

  const auto cid = generator.GenerateNextConnectionId(quic::test::TestConnectionId(0x1234));
  ASSERT_TRUE(cid.has_value());
  ASSERT_EQ(cid->length(), 10);
  // The stable prefix is copied from the original connection ID.
  EXPECT_EQ(memcmp(cid->data(), quic::test::TestConnectionId(0x1234).data(), 4), 0);
  EXPECT_EQ(cid->data()[8], 3);
  EXPECT_EQ(cid->data()[9], 7);
}

struct SelectorTestCase {
  std::vector<uint8_t> packet;
  uint32_t concurrency;
  uint32_t expected;
};

constexpr uint32_t kDefaultWorker = 99;

class EpochStableSelectorTest : public testing::TestWithParam<SelectorTestCase> {};

INSTANTIATE_TEST_SUITE_P(
    Packets, EpochStableSelectorTest,
    testing::Values(
        // Short header: flags | dcid(8) | generation | worker index.
        SelectorTestCase{{0x00, 1, 2, 3, 4, 5, 6, 7, 8, /*generation=*/0, /*worker=*/1}, 2, 1},
        // Short header with an out of range worker index.
        SelectorTestCase{
            {0x00, 1, 2, 3, 4, 5, 6, 7, 8, /*generation=*/0, /*worker=*/5}, 2, kDefaultWorker},
        // Short header too short to carry a routable connection ID.
        SelectorTestCase{{0x00, 1, 2, 3}, 2, kDefaultWorker},
        // Long header: flags | version(4) | dcid_len | dcid; routed by the first four connection
        // ID bytes interpreted as a native-endian u32 modulo concurrency.
        SelectorTestCase{{0x80, 0, 0, 0, 1, /*dcid_len=*/8, 3, 0, 0, 0, 5, 6, 7, 8}, 2, 1},
        // Long header with a connection ID shorter than the stable prefix.
        SelectorTestCase{{0x80, 0, 0, 0, 1, /*dcid_len=*/4, 3, 0, 0, 0}, 2, kDefaultWorker},
        // Long header too short to carry the stable prefix.
        SelectorTestCase{{0x80, 0, 0, 0, 1, /*dcid_len=*/8, 3}, 2, kDefaultWorker},
        // Empty packet.
        SelectorTestCase{{}, 2, kDefaultWorker}));

TEST_P(EpochStableSelectorTest, RoutesLikeTheBpfProgram) {
  NiceMock<Network::MockListenSocketFactory> listen_socket_factory;
  Factory factory(listen_socket_factory);

  const auto& test_case = GetParam();
  const auto selector = factory.getCompatibleConnectionIdWorkerSelector(test_case.concurrency);

  Buffer::OwnedImpl packet;
  packet.add(test_case.packet.data(), test_case.packet.size());
  EXPECT_EQ(selector(packet, kDefaultWorker), test_case.expected);
}

} // namespace
} // namespace EpochStable
} // namespace ConnectionIdGenerator
} // namespace Extensions
} // namespace Quic
} // namespace Envoy
