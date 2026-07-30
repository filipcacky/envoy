#include "source/common/network/bpf_syscalls.h"

#include <array>
#include <cerrno>

#ifdef ENVOY_EBPF_SUPPORTED
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#endif

namespace Envoy {
namespace Network {

#ifdef ENVOY_EBPF_SUPPORTED

Api::SysCallPtrResult BpfSysCallsImpl::bpfObjectOpenMem(const void* data, size_t size) {
  bpf_object* object = bpf_object__open_mem(data, size, nullptr);
  return {object, object == nullptr ? errno : 0};
}

Api::SysCallIntResult BpfSysCallsImpl::bpfObjectLoad(bpf_object* object) {
  const int rc = bpf_object__load(object);
  return {rc, rc < 0 ? errno : 0};
}

bpf_program* BpfSysCallsImpl::bpfObjectFindProgramByName(bpf_object* object, const char* name) {
  return bpf_object__find_program_by_name(object, name);
}

bpf_map* BpfSysCallsImpl::bpfObjectFindMapByName(bpf_object* object, const char* name) {
  return bpf_object__find_map_by_name(object, name);
}

Api::SysCallIntResult BpfSysCallsImpl::bpfProgramFd(const bpf_program* program) {
  const int fd = bpf_program__fd(program);
  return {fd, fd < 0 ? errno : 0};
}

Api::SysCallIntResult BpfSysCallsImpl::bpfMapFd(const bpf_map* map) {
  const int fd = bpf_map__fd(map);
  return {fd, fd < 0 ? errno : 0};
}

uint32_t BpfSysCallsImpl::bpfMapMaxEntries(const bpf_map* map) { return bpf_map__max_entries(map); }

void BpfSysCallsImpl::bpfObjectClose(bpf_object* object) { bpf_object__close(object); }

Api::SysCallIntResult
BpfSysCallsImpl::bpfProgGetMapIds(os_fd_t prog_fd, absl::Span<uint32_t> map_ids, uint32_t& count) {
  bpf_prog_info info{};
  __u32 info_len = sizeof(info);
  info.nr_map_ids = map_ids.size();
  info.map_ids = reinterpret_cast<__u64>(map_ids.data());

  const int rc = bpf_prog_get_info_by_fd(prog_fd, &info, &info_len);
  if (rc < 0) {
    return {rc, errno};
  }
  count = info.nr_map_ids;
  return {rc, 0};
}

Api::SysCallIntResult BpfSysCallsImpl::bpfMapGetInfoByFd(os_fd_t map_fd, BpfMapInfo& info) {
  bpf_map_info map_info{};
  __u32 map_info_len = sizeof(map_info);
  const int rc = bpf_map_get_info_by_fd(map_fd, &map_info, &map_info_len);
  if (rc < 0) {
    return {rc, errno};
  }
  info.name_ = map_info.name;
  info.max_entries_ = map_info.max_entries;
  return {rc, 0};
}

Api::SysCallSocketResult BpfSysCallsImpl::bpfMapGetFdById(uint32_t id) {
  const int fd = bpf_map_get_fd_by_id(id);
  return {fd, fd < 0 ? errno : 0};
}

Api::SysCallSocketResult BpfSysCallsImpl::bpfMapCreateReuseportSockArray(uint32_t max_entries,
                                                                         const char* name) {
  bpf_map_create_opts opts{};
  opts.sz = sizeof(opts);
  const int fd = bpf_map_create(BPF_MAP_TYPE_REUSEPORT_SOCKARRAY, name, sizeof(uint32_t),
                                sizeof(uint32_t), max_entries, &opts);
  return {fd, fd < 0 ? errno : 0};
}

Api::SysCallIntResult BpfSysCallsImpl::bpfMapLookupElem(os_fd_t map_fd, const void* key,
                                                        void* value) {
  const int rc = bpf_map_lookup_elem(map_fd, key, value);
  return {rc, rc < 0 ? errno : 0};
}

Api::SysCallIntResult BpfSysCallsImpl::bpfMapUpdateElem(os_fd_t map_fd, const void* key,
                                                        const void* value) {
  const int rc = bpf_map_update_elem(map_fd, key, value, BPF_ANY);
  return {rc, rc < 0 ? errno : 0};
}

#else // ENVOY_EBPF_SUPPORTED

Api::SysCallPtrResult BpfSysCallsImpl::bpfObjectOpenMem(const void*, size_t) {
  return {nullptr, ENOTSUP};
}

Api::SysCallIntResult BpfSysCallsImpl::bpfObjectLoad(bpf_object*) { return {-1, ENOTSUP}; }

bpf_program* BpfSysCallsImpl::bpfObjectFindProgramByName(bpf_object*, const char*) {
  return nullptr;
}

bpf_map* BpfSysCallsImpl::bpfObjectFindMapByName(bpf_object*, const char*) { return nullptr; }

Api::SysCallIntResult BpfSysCallsImpl::bpfProgramFd(const bpf_program*) { return {-1, ENOTSUP}; }

Api::SysCallIntResult BpfSysCallsImpl::bpfMapFd(const bpf_map*) { return {-1, ENOTSUP}; }

uint32_t BpfSysCallsImpl::bpfMapMaxEntries(const bpf_map*) { return 0; }

void BpfSysCallsImpl::bpfObjectClose(bpf_object*) {}

Api::SysCallIntResult BpfSysCallsImpl::bpfProgGetMapIds(os_fd_t, absl::Span<uint32_t>, uint32_t&) {
  return {-1, ENOTSUP};
}

Api::SysCallIntResult BpfSysCallsImpl::bpfMapGetInfoByFd(os_fd_t, BpfMapInfo&) {
  return {-1, ENOTSUP};
}

Api::SysCallSocketResult BpfSysCallsImpl::bpfMapGetFdById(uint32_t) {
  return {INVALID_SOCKET, ENOTSUP};
}

Api::SysCallSocketResult BpfSysCallsImpl::bpfMapCreateReuseportSockArray(uint32_t, const char*) {
  return {INVALID_SOCKET, ENOTSUP};
}

Api::SysCallIntResult BpfSysCallsImpl::bpfMapLookupElem(os_fd_t, const void*, void*) {
  return {-1, ENOTSUP};
}

Api::SysCallIntResult BpfSysCallsImpl::bpfMapUpdateElem(os_fd_t, const void*, const void*) {
  return {-1, ENOTSUP};
}

#endif // ENVOY_EBPF_SUPPORTED

} // namespace Network
} // namespace Envoy
