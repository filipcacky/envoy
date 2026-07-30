#pragma once

#include <cstdint>
#include <string>

#include "envoy/api/os_sys_calls_common.h"
#include "envoy/common/platform.h"
#include "envoy/common/pure.h"

#include "source/common/singleton/threadsafe_singleton.h"

#include "absl/types/span.h"

// All of the eBPF machinery requires the ability to attach an eBPF program to a reuseport group.
#if defined(SO_ATTACH_REUSEPORT_EBPF) && defined(__linux__)
#define ENVOY_EBPF_SUPPORTED
#endif

struct bpf_object;
struct bpf_program;
struct bpf_map;

namespace Envoy {
namespace Network {

struct BpfMapInfo {
  std::string name_;
  uint32_t max_entries_{0};
};

// Thin shim over the libbpf calls used by Envoy, one virtual per libbpf function.
// On platforms without eBPF support all calls fail with ENOTSUP.
class BpfSysCalls {
public:
  virtual ~BpfSysCalls() = default;

  virtual Api::SysCallPtrResult bpfObjectOpenMem(const void* data, size_t size) PURE;
  virtual Api::SysCallIntResult bpfObjectLoad(bpf_object* object) PURE;
  virtual bpf_program* bpfObjectFindProgramByName(bpf_object* object, const char* name) PURE;
  virtual bpf_map* bpfObjectFindMapByName(bpf_object* object, const char* name) PURE;
  virtual Api::SysCallIntResult bpfProgramFd(const bpf_program* program) PURE;
  virtual Api::SysCallIntResult bpfMapFd(const bpf_map* map) PURE;
  virtual uint32_t bpfMapMaxEntries(const bpf_map* map) PURE;
  virtual void bpfObjectClose(bpf_object* object) PURE;

  // Wraps bpf_prog_get_info_by_fd, returning the ids of the maps used by the program.
  virtual Api::SysCallIntResult bpfProgGetMapIds(os_fd_t prog_fd, absl::Span<uint32_t> map_ids,
                                                 uint32_t& count) PURE;
  // Wraps bpf_map_get_info_by_fd.
  virtual Api::SysCallIntResult bpfMapGetInfoByFd(os_fd_t map_fd, BpfMapInfo& info) PURE;
  // Returns the fd of the map with the given id.
  virtual Api::SysCallSocketResult bpfMapGetFdById(uint32_t id) PURE;

  // Creates a BPF_MAP_TYPE_REUSEPORT_SOCKARRAY map and returns its fd.
  virtual Api::SysCallSocketResult bpfMapCreateReuseportSockArray(uint32_t max_entries,
                                                                  const char* name) PURE;
  virtual Api::SysCallIntResult bpfMapLookupElem(os_fd_t map_fd, const void* key, void* value) PURE;
  virtual Api::SysCallIntResult bpfMapUpdateElem(os_fd_t map_fd, const void* key,
                                                 const void* value) PURE;
};

class BpfSysCallsImpl : public BpfSysCalls {
public:
  Api::SysCallPtrResult bpfObjectOpenMem(const void* data, size_t size) override;
  Api::SysCallIntResult bpfObjectLoad(bpf_object* object) override;
  bpf_program* bpfObjectFindProgramByName(bpf_object* object, const char* name) override;
  bpf_map* bpfObjectFindMapByName(bpf_object* object, const char* name) override;
  Api::SysCallIntResult bpfProgramFd(const bpf_program* program) override;
  Api::SysCallIntResult bpfMapFd(const bpf_map* map) override;
  uint32_t bpfMapMaxEntries(const bpf_map* map) override;
  void bpfObjectClose(bpf_object* object) override;
  Api::SysCallIntResult bpfProgGetMapIds(os_fd_t prog_fd, absl::Span<uint32_t> map_ids,
                                         uint32_t& count) override;
  Api::SysCallIntResult bpfMapGetInfoByFd(os_fd_t map_fd, BpfMapInfo& info) override;
  Api::SysCallSocketResult bpfMapGetFdById(uint32_t id) override;
  Api::SysCallSocketResult bpfMapCreateReuseportSockArray(uint32_t max_entries,
                                                          const char* name) override;
  Api::SysCallIntResult bpfMapLookupElem(os_fd_t map_fd, const void* key, void* value) override;
  Api::SysCallIntResult bpfMapUpdateElem(os_fd_t map_fd, const void* key,
                                         const void* value) override;
};

using BpfSysCallsSingleton = ThreadSafeSingleton<BpfSysCallsImpl>;

} // namespace Network
} // namespace Envoy
