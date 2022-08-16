#include <errno.h>
#include <netdb.h>
#include <pthread.h>
#include <signal.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/inotify.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <filesystem>
#include <string_view>
#include <thread>
#include <vector>

#include <absl/synchronization/mutex.h>
#include <spdlog/spdlog.h>

#include "connection.h"
#include "fs.h"
#include "gencache.h"
#include "srync.h"

static unique_fd connect_socket(const std::string& host, int port) {
  std::string port_str = std::to_string(port);
  struct addrinfo* ai;
  struct addrinfo hints = {
    .ai_flags = AI_V4MAPPED | AI_ADDRCONFIG | AI_NUMERICSERV,
    .ai_family = AF_UNSPEC,
    .ai_socktype = SOCK_STREAM,
    .ai_protocol = 0,
    .ai_addrlen = 0,
    .ai_addr = nullptr,
    .ai_canonname = nullptr,
    .ai_next = nullptr,
  };

  if (int rc = getaddrinfo(host.c_str(), port_str.c_str(), &hints, &ai); rc != 0) {
    ERROR("Failed to resolve host '{}': {}", host, gai_strerror(rc));
    return {};
  }

  unique_fd sockfd;
  bool connected = false;
  for (struct addrinfo* p = ai; p; p = p->ai_next) {
    sockfd.reset(socket(p->ai_family, p->ai_socktype | SOCK_CLOEXEC, p->ai_protocol));
    if (sockfd == -1) {
      continue;
    }
    if (connect(sockfd.get(), p->ai_addr, p->ai_addrlen) != -1) {
      connected = true;
      break;
    }
  }
  freeaddrinfo(ai);

  if (!connected) {
    ERROR("Failed to connect to {}:{}: {}", host, port, strerror(errno));
    return {};
  }

  if (fcntl(sockfd.get(), F_SETFL, O_NONBLOCK) != 0) {
    ERROR("Failed to make socket nonblocking: {}", strerror(errno));
    return {};
  }

  return sockfd;
}

struct ReadRequest {
  fuse_req_t req;
  uint64_t size;
  uint64_t offset;
};

struct PriorityBlock {
  absl::Mutex mutex_;
  std::vector<UpdateId> prioritized_ ABSL_GUARDED_BY(mutex_);
};

struct ClientFileProvider : public FileProvider {
  explicit ClientFileProvider(FileId file_id, UpdateId update_id, Checksum checksum, unique_fd fd,
                              uint64_t expected_size, PriorityBlock* priority_block)
      : file_id_(file_id),
        update_id_(update_id),
        checksum_(checksum),
        fd_(std::move(fd)),
        expected_size_(expected_size),
        priority_block_(priority_block) {}

  virtual void read(fuse_req_t req, uint64_t size, uint64_t offset) override final {
    absl::MutexLock lock(&mutex_);
    requests_.push_back(ReadRequest{
      .req = req,
      .size = size,
      .offset = offset,
    });

    if (!this->prioritized_) {
      absl::MutexLock lock(&priority_block_->mutex_);
      this->prioritized_ = true;
      priority_block_->prioritized_.push_back(update_id_);
    }
    fulfill_requests();
  }

  bool write(const char* buf, size_t len) {
    while (len != 0) {
      ssize_t rc = TEMP_FAILURE_RETRY(::write(fd_.get(), buf, len));
      if (rc == -1) {
        ERROR("Failed to write to file: {}", strerror(errno));
        return false;
      }
      buf += rc;
      len -= rc;
      size_.fetch_add(rc);
    }

    absl::MutexLock lock(&mutex_);
    fulfill_requests();
    return true;
  }

  void fulfill_requests() ABSL_EXCLUSIVE_LOCKS_REQUIRED(mutex_) {
    auto it = requests_.begin();
    while (it != requests_.end()) {
      if (it->offset >= expected_size_) {
        ERROR("Received read past the end of the file (offset = {})", it->offset);
        fuse_reply_err(it->req, 0);
        it = requests_.erase(it);
        continue;
      }

      // We're not using direct I/O, so requests have to be fully satisfied.
      if (size_ != expected_size_ && it->offset + it->size >= size_) {
        ++it;
        continue;
      }

      static_assert(sizeof(off_t) == sizeof(uint64_t));
      uint64_t bytes_available = size_ - it->offset;
      uint64_t len = std::min(bytes_available, it->size);
      if (len > 256 * 1024) {
        ERROR("Received read request of size {}, expected max of 256kiB readahead", len);
      }

      Block buffer(len);
      ssize_t rc = TEMP_FAILURE_RETRY(pread(fd_.get(), buffer.data(), buffer.size(), it->offset));
      if (rc == -1) {
        int err = errno;
        ERROR("Failed to pread from cache file: {}", strerror(err));
        fuse_reply_err(it->req, err);
      } else {
        fuse_reply_buf(it->req, buffer.data(), rc);
      }

      it = requests_.erase(it);
    }
  }

  const FileId file_id_;
  const UpdateId update_id_;
  const Checksum checksum_;

  unique_fd fd_;
  const uint64_t expected_size_;

  absl::Mutex mutex_;
  std::atomic<uint64_t> size_ = 0;
  std::vector<ReadRequest> requests_ ABSL_GUARDED_BY(mutex_);

  PriorityBlock* priority_block_;
  bool prioritized_ = false;
};

struct ServerConnection : public Connection {
  ServerConnection(borrowed_fd epollfd, unique_fd fd, Fs& fs, GenerationCache& cache)
      : Connection(epollfd, std::move(fd)), fs_(fs), cache_(cache) {}

  void init() {
    Block buf(sizeof(ClientHello) + sizeof(ChecksumAlgorithm));
    auto hello = reinterpret_cast<ClientHello*>(buf.data());
    hello->version = SRYNC_PROTOCOL_VERSION;
    hello->padding = 0;
    hello->eager = 1;
    hello->checksum_count = 1;
    hello->available_checksums[0] = ChecksumAlgorithm::TimestampAndSize;

    this->write(CommandType::ClientHello, std::move(buf));
  }

  bool send_file_generations(FileId id) {
    absl::MutexLock lock(&cache_.files_mutex_);
    auto it = cache_.files_.find(id);
    if (it == cache_.files_.end()) {
      ERROR("Failed to find file in cache");
      return false;
    }

    uint8_t generation_count = std::min(255UL, it->second.generations.size());
    Block buf(sizeof(ReportFileVersions) + generation_count * sizeof(ChecksumAlgorithm));
    auto* p = reinterpret_cast<ReportFileVersions*>(buf.data());
    p->file_id = id;
    p->padding = 0;
    p->checksum_count = generation_count;
    size_t i = 0;
    for (auto& generation : it->second.generations) {
      memcpy(&p->checksums[i++], &generation, sizeof(generation));
    }
    INFO("{}: sending {} generations", it->second.filename, generation_count);
    this->write(CommandType::ReportFileVersions, std::move(buf));
    return true;
  }

  bool handle_hello(Block& data) {
    auto p = packet_cast<ServerHello>(data);
    if (!p) {
      return false;
    }
    INFO("Received ServerHello: checksum={}", p->selected_checksum);
    return true;
  }

  bool handle_die(Block& data) {
    auto p = packet_cast<ServerDie>(data);
    if (!p) {
      return false;
    }

    std::string_view message(p->message, p->message_length);
    ERROR("Received error from server: {}", message);
    return false;
  }

  bool handle_add_file(Block& data) {
    auto p = packet_cast<AddFile>(data);
    if (!p) {
      return false;
    }

    std::string_view filename(p->filename, p->filename_length);
    INFO("Server added a new file: {} => '{}'", p->file_id, filename);
    cache_.register_file(p->file_id, std::string(filename));
    if (!send_file_generations(p->file_id)) {
      return false;
    }

    return true;
  }

  bool handle_begin_file_update(Block& data) {
    auto p = packet_cast<BeginFileUpdate>(data);
    if (!p) {
      return false;
    }

    std::optional<std::string> filename = cache_.filename(p->file_id);
    if (!filename) {
      ERROR("Failed to get filename for updated file");
      return false;
    }

    unique_fd fd = cache_.open_tmpfile();
    if (fd == -1) {
      ERROR("Failed to open cache file for writing: {}", strerror(errno));
      return false;
    }

    auto fp = std::make_shared<ClientFileProvider>(p->file_id, p->update_id, p->new_checksum,
                                                   std::move(fd), p->size, &priority_block_);
    fs_.add_file(std::move(*filename), p->mtime, p->size, fp);
    updates_[p->update_id] = std::move(fp);

    INFO("Received BeginFileUpdate: id={} file={}", p->update_id, p->file_id);
    return true;
  }

  bool handle_file_update(Block& data) {
    auto p = packet_cast<FileUpdate>(data);
    if (!p) {
      return false;
    }

    DEBUG("Received FileUpdate: id={} data={}", p->update_id, p->data_length);
    auto it = updates_.find(p->update_id);
    if (it == updates_.end()) {
      ERROR("No active record found for FileUpdate: id={}", p->update_id);
      return false;
    }

    if (!it->second->write(p->data, p->data_length)) {
      return false;
    }

    send_priority_updates();
    return true;
  }

  void send_priority_updates() {
    std::vector<UpdateId> priority;

    {
      absl::MutexLock lock(&priority_block_.mutex_);
      std::swap(priority, priority_block_.prioritized_);
    }

    for (UpdateId id : priority) {
      Block buf(sizeof(SetUpdatePriority));
      auto p = reinterpret_cast<SetUpdatePriority*>(buf.data());
      p->update_id = id;
      p->priority = 0;
      write(CommandType::SetUpdatePriority, std::move(buf));

      INFO("Prioritizing update {}", id);
    }
  }

  bool handle_end_file_update(Block& data) {
    auto p = packet_cast<EndFileUpdate>(data);
    if (!p) {
      return false;
    }

    INFO("Received EndFileUpdate: id={}, success={}", p->update_id, static_cast<bool>(p->success));
    auto it = updates_.find(p->update_id);
    if (it == updates_.end()) {
      ERROR("No active record found for EndFileUpdate: id={}", p->update_id);
      return false;
    }

    if (p->success) {
      if (!cache_.add_version(it->second->file_id_, it->second->checksum_, it->second->fd_, true)) {
        ERROR("Failed to link file into cache");
        return false;
      }
    } else {
      WARN("Server reported failure for update {}", p->update_id);
    }
    updates_.erase(it);
    return true;
  }

  bool process_read(const PacketHeader& header, Block data) override final {
    switch (header.type) {
      case CommandType::ServerHello:
        return handle_hello(data);
      case CommandType::ServerDie:
        return handle_die(data);
      case CommandType::AddFile:
        return handle_add_file(data);
      case CommandType::BeginFileUpdate:
        return handle_begin_file_update(data);
      case CommandType::FileUpdate:
        return handle_file_update(data);
      case CommandType::EndFileUpdate:
        return handle_end_file_update(data);
      default:
        WARN("Unhandled packet type: {}", header.type);
        return false;
    }
    return true;
  }

  Fs& fs_;
  GenerationCache& cache_;

  PriorityBlock priority_block_;

  absl::flat_hash_map<UpdateId, std::shared_ptr<ClientFileProvider>> updates_;
};

int client_main(std::string host, int port, std::filesystem::path mountpoint) {
  INFO("srync client v" SRYNC_VERSION " starting...");

  unique_fd killfd(eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK));
  if (killfd == -1) {
    ERROR("eventfd failed: {}", strerror(errno));
    exit(1);
  }

  if (!getenv("HOME")) {
    ERROR("$HOME is unset");
    exit(1);
  }
  std::filesystem::path cachedir = fmt::format("{}/.srync/client", getenv("HOME"));

  GenerationCache cache(std::move(cachedir), ChecksumAlgorithm::TimestampAndSize);
  if (!cache.init()) {
    ERROR("Failed to initialize generation cache, exiting");
    exit(1);
  }

  Fs fs;
  if (!fs.mount(mountpoint)) {
    ERROR("Failed to mount FUSE filesystem at '{}', aborting.", mountpoint.c_str());
    exit(1);
  }

  INFO("Successfully mounted FUSE filesystem at '{}'", mountpoint.c_str());
  pthread_t main_thread = pthread_self();

  std::thread connection_thread([&fs, &cache, &host, port, &killfd, main_thread]() {
    unique_fd fd = connect_socket(host, port);
    if (fd == -1) {
      pthread_kill(main_thread, SIGINT);
      return;
    }

    unique_fd epfd(epoll_create1(EPOLL_CLOEXEC));
    if (epfd == -1) {
      ERROR("Failed to create epoll fd: {}", strerror(errno));
      pthread_kill(main_thread, SIGINT);
      return;
    }

    struct epoll_event event;
    event.events = EPOLLIN;
    event.data.fd = killfd.get();
    if (epoll_ctl(epfd.get(), EPOLL_CTL_ADD, killfd.get(), &event) != 0) {
      ERROR("epoll_ctl failed to add killfd: {}", strerror(errno));
      pthread_kill(main_thread, SIGINT);
      return;
    }

    ServerConnection connection(epfd, std::move(fd), fs, cache);
    connection.init();
    INFO("Successfully connected to {}:{}", host, port);
    while (true) {
      std::array<struct epoll_event, 8> events;
      int rc = TEMP_FAILURE_RETRY(epoll_wait(epfd.get(), events.data(), events.size(), -1));
      if (rc == -1) {
        ERROR("epoll_wait failed: {}", strerror(errno));
        pthread_kill(main_thread, SIGINT);
        return;
      }

      for (size_t i = 0; i < static_cast<size_t>(rc); ++i) {
        struct epoll_event* event = &events[i];
        if (event->data.fd == killfd.get()) {
          INFO("Connection thread exiting");
          return;
        } else if (event->data.fd == connection.pollfd().get()) {
          if (!connection.process_events(event->events)) {
            ERROR("Terminating server connection");
            pthread_kill(main_thread, SIGINT);
            return;
          }
          continue;
        }

        ERROR("Unknown epoll event: {}", static_cast<int>(event->data.fd));
        pthread_kill(main_thread, SIGINT);
        return;
      }
    }
  });

  fs.run();

  INFO("srync exiting");
  uint64_t x = 1;
  if (TEMP_FAILURE_RETRY(write(killfd.get(), &x, sizeof(x))) != sizeof(x)) {
    ERROR("Failed to signal connection thread to exit");
    exit(1);
  }
  connection_thread.join();
  return 0;
}
