#include "afterfree.h"
#include "common.hpp"
#include "emulator.hpp"
#include "native_replay.hpp"
#include "sandbox.hpp"
#include "transport.hpp"
#include <algorithm>
#include <cstdio>
#include <fcntl.h>
#include <malloc.h>
#include <map>
#include <memory>
#include <openssl/sha.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <unicorn/unicorn.h>

namespace af {
af_worker_profile profile{};
struct ProtocolFailure : std::runtime_error {
  using std::runtime_error::runtime_error;
};
struct Stored {
  Recipe recipe;
  std::unique_ptr<NativeReplay> native;
  uint64_t retained() const {
    uint64_t n = sizeof(*this) + 64 + recipe.pages.capacity() * 8 +
                 recipe.code.capacity() * sizeof(Instruction) +
                 recipe.inputs.capacity() * sizeof(Segment);
    for (auto &input : recipe.inputs)
      n += input.bytes.capacity();
    return n + (native ? native->retained_bytes() : 0);
  }
};
struct Output {
  uint8_t *data;
  uint64_t mapped;
  explicit Output(uint64_t size) : mapped(rounded(size)) {
    Timer timer(profile.arena_ns);
    data = static_cast<uint8_t *>(
        mmap(nullptr, mapped, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
    if (data == MAP_FAILED)
      throw std::bad_alloc();
    madvise(data, mapped, MADV_DONTDUMP);
  }
  ~Output() {
    Timer timer(profile.arena_ns);
    munmap(data, mapped);
  }
};
static bool respond(int fd, uint64_t status, const std::string &msg, const uint8_t *data = nullptr,
                    size_t size = 0) {
  Timer timer(profile.send_ns);
  Response r;
  r.status = status;
  r.size = size;
  std::snprintf(r.message, sizeof r.message, "%s", msg.c_str());
  return write_all(fd, &r, sizeof r) && (!size || write_all(fd, data, size));
}
} // namespace af
int main(int argc, char **argv) {
  using namespace af;
  if (argc != 2 && (argc != 3 || std::strcmp(argv[2], "shared")))
    return 2;
  int fd = std::atoi(argv[1]);
  if (fd < 3)
    return 2;
  SharedArena arena;
  if (argc == 3 && !arena.receive(fd))
    return 2;
  prctl(PR_SET_PDEATHSIG, SIGKILL);
  prctl(PR_SET_DUMPABLE, 0);
  prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
  struct rlimit core {
    0, 0
  };
  setrlimit(RLIMIT_CORE, &core);
  // Resolve lazy initialization before revoking filesystem and network access.
  uint8_t warm_digest[32];
  if (!SHA256(nullptr, 0, warm_digest))
    return 2;
  try {
    restrict_worker(fd);
  } catch (const std::exception &e) {
    respond(fd, 1, e.what());
    return 2;
  }
  std::map<uint64_t, std::unique_ptr<Stored>> recipes;
  uint64_t bytes = 0;
  for (;;) {
    Request q;
    if (!read_all(fd, &q, sizeof q))
      break;
    profile.requests++;
    if (q.command == PROFILE) {
      rusage usage{};
      getrusage(RUSAGE_SELF, &usage);
      profile.user_ns =
          uint64_t(usage.ru_utime.tv_sec) * 1000000000 + usage.ru_utime.tv_usec * 1000;
      profile.system_ns =
          uint64_t(usage.ru_stime.tv_sec) * 1000000000 + usage.ru_stime.tv_usec * 1000;
      if (!respond(fd, 0, "profile", reinterpret_cast<const uint8_t *>(&profile), sizeof profile))
        break;
      continue;
    }
    if (q.command == QUIT)
      break;
    if (q.command == POLICY_PROBE) {
      errno = 0;
      int network = socket(AF_INET, SOCK_STREAM, 0);
      bool network_denied = network < 0 && errno == EPERM;
      errno = 0;
      int file = open("/tmp/afterfree-worker-policy-probe", O_WRONLY | O_CREAT | O_EXCL, 0600);
      bool file_denied = file < 0 && errno == EPERM;
      if (network >= 0)
        close(network);
      if (file >= 0)
        close(file);
      if (!respond(fd, network_denied && file_denied ? 0 : 1, "network and file writes denied"))
        break;
      continue;
    }
    if (q.command == PING) {
      char pid[64]{};
      auto n = readlink("/proc/self", pid, sizeof pid - 1);
      if (n < 1 || !respond(fd, 0, pid))
        break;
      continue;
    }
    if (q.command == DROP) {
      auto it = recipes.find(q.id);
      if (it != recipes.end()) {
        bytes -= it->second->retained();
        recipes.erase(it);
      }
      if (!respond(fd, 0, "dropped"))
        break;
      malloc_trim(0);
      continue;
    }
    if (q.command == PEAK_RSS) {
      rusage usage{};
      if (getrusage(RUSAGE_SELF, &usage) ||
          !respond(fd, 0, std::to_string(uint64_t(usage.ru_maxrss) * 1024)))
        break;
      continue;
    }
    if (q.command == PUT || q.command == REGISTER || q.command == REGISTER_STREAM) {
      if (q.size > MAX_BLOB || q.size < sizeof(Header)) {
        respond(fd, 1, "invalid protocol size");
        break;
      }
      if (bytes + q.size > (512ULL << 20)) {
        uint8_t chunk[4096];
        uint64_t left = q.size;
        bool ok = true;
        while (left) {
          size_t n = std::min(uint64_t(sizeof chunk), left);
          if (!read_all(fd, chunk, n)) {
            ok = false;
            break;
          }
          left -= n;
        }
        if (!ok || !respond(fd, 1, "worker recipe budget exceeded"))
          break;
        continue;
      }
      std::vector<uint8_t> blob(q.size);
      if (!read_all(fd, blob.data(), blob.size()))
        break;
      try {
        auto value = std::make_unique<Stored>();
        {
          Timer timer(profile.decode_ns);
          value->recipe = decode(blob);
        }
        std::vector<uint8_t>().swap(blob);
        std::unique_ptr<Output> output;
        std::unique_ptr<Replay> emulator;
        const uint8_t *validated = nullptr;
        bool streaming = q.command == REGISTER_STREAM;
        if (streaming && !arena.data)
          throw std::runtime_error("streaming requires a shared window");
        uint64_t sent = 0;
        auto publish = [&](const uint8_t *data, size_t length) {
          Timer timer(profile.send_ns);
          if (data != arena.data)
            std::memcpy(arena.data, data, length);
          Response chunk;
          chunk.size = length;
          Request ack;
          sent += length;
          if (!write_all(fd, &chunk, sizeof chunk) || !read_all(fd, &ack, sizeof ack) ||
              ack.command != STREAM_ACK || ack.id != q.id || ack.size != sent)
            throw ProtocolFailure("validation window acknowledgement failed");
        };
        std::string message = "native replay validated";
        try {
          {
            Timer timer(profile.compile_ns);
            value->native = std::make_unique<NativeReplay>(value->recipe, profile);
          }
          if (streaming) {
            Timer timer(profile.validate_ns);
            value->native->validate_stream(arena.data, arena.capacity, publish);
          } else {
            output = std::make_unique<Output>(value->recipe.h.length);
            {
              Timer timer(profile.validate_ns);
              value->native->run(output->data, 0, value->recipe.h.length, true);
            }
            validated = output->data;
          }
        } catch (const ProtocolFailure &) {
          throw;
        } catch (const std::exception &e) {
          message = std::string("emulator replay validated; native: ") + e.what();
          value->native.reset();
          output.reset();
          {
            Timer timer(profile.validate_ns);
            emulator = std::make_unique<Replay>();
            emulator->run(value->recipe);
          }
          validated = emulator->output;
          if (streaming) {
            // Restart full byte comparison after a failed speculative native
            // stream. Nothing was committed and the original remains resident.
            if (!respond(fd, 2, "restart comparison with strict emulator"))
              break;
            sent = 0;
            for (uint64_t offset = 0; offset < value->recipe.h.length; offset += arena.capacity)
              publish(validated + offset,
                      std::min(uint64_t(arena.capacity), value->recipe.h.length - offset));
          }
        }
        auto it = recipes.find(q.id);
        auto old_size = it != recipes.end() ? it->second->retained() : 0;
        auto new_size = value->retained();
        if (bytes - old_size + new_size > (512ULL << 20))
          throw std::runtime_error("worker recipe budget exceeded");
        Registration registration{value->native ? 1ULL : 0ULL,
                                  value->native && value->native->pageable() ? PAGE : 0, new_size};
        auto length = value->recipe.h.length;
        recipes[q.id] = std::move(value);
        bytes = bytes - old_size + new_size;
        // Commit before acknowledging: an allocation failure cannot authorize
        // eviction of data whose recipe was never retained by the worker.
        if (streaming) {
          Response response;
          std::snprintf(response.message, sizeof response.message, "%s", message.c_str());
          if (!write_all(fd, &response, sizeof response) ||
              !write_all(fd, &registration, sizeof registration))
            break;
        } else if (q.command == REGISTER) {
          Timer timer(profile.send_ns);
          Response response;
          response.size = length;
          std::snprintf(response.message, sizeof response.message, "%s", message.c_str());
          if (!write_all(fd, &response, sizeof response) ||
              !write_all(fd, &registration, sizeof registration) ||
              !write_all(fd, validated, length))
            break;
        } else if (!respond(fd, 0, message, validated, length))
          break;
      } catch (const std::exception &e) {
        if (!respond(fd, 1, e.what()))
          break;
      }
    } else if (q.command == RESTORE || q.command == RESTORE_RANGE || q.command == RESTORE_SHARED) {
      auto it = recipes.find(q.id);
      if (it == recipes.end()) {
        if (!respond(fd, 1, "recipe not found"))
          break;
        continue;
      }
      try {
        auto &stored = *it->second;
        bool range = q.command != RESTORE;
        bool shared = q.command == RESTORE_SHARED;
        uint64_t offset = range ? q.size >> 32 : 0;
        uint64_t length = range ? uint32_t(q.size) : stored.recipe.h.length;
        if (!length || offset > stored.recipe.h.length ||
            length > stored.recipe.h.length - offset ||
            (shared && (!arena.data || length > arena.capacity)) ||
            (range && (!stored.native || !stored.native->pageable() || offset % PAGE ||
                       (length % PAGE && offset + length != stored.recipe.h.length))))
          throw std::runtime_error("invalid reconstruction range");
        if (shared) {
          {
            Timer timer(profile.restore_ns);
            stored.native->run(arena.data, offset, length);
          }
          Response response;
          response.size = length;
          if (!write_all(fd, &response, sizeof response))
            break;
        } else if (stored.native) {
          Output output(length);
          {
            Timer timer(profile.restore_ns);
            stored.native->run(output.data, offset, length);
          }
          if (!respond(fd, 0, "restored", output.data, length))
            break;
        } else {
          Replay replay;
          {
            Timer timer(profile.restore_ns);
            replay.run(stored.recipe, false);
          }
          if (!respond(fd, 0, "restored", replay.output, replay.length))
            break;
        }
      } catch (const std::exception &e) {
        if (!respond(fd, 1, e.what()))
          break;
      }
    } else {
      respond(fd, 1, "unknown command");
      break;
    }
    if (q.command == REGISTER || q.command == PUT || q.command == REGISTER_STREAM) {
      Timer timer(profile.trim_ns);
      malloc_trim(0);
    }
  }
  close(fd);
  return 0;
}
