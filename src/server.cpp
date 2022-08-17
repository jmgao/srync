#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/ip.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/inotify.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <array>
#include <deque>
#include <filesystem>
#include <vector>

#include <absl/container/btree_map.h>
#include <absl/container/btree_set.h>
#include <absl/container/flat_hash_map.h>
#include <absl/container/flat_hash_set.h>
#include <absl/synchronization/mutex.h>
#include <absl/types/span.h>
#include <spdlog/spdlog.h>

#include "connection.h"
#include "gencache.h"
#include "iovector.h"
#include "srync.h"
#include "update_engine.h"

static unique_fd listen_socket(const std::string& host, int port) {
  std::string port_str = std::to_string(port);
  struct addrinfo* ai;
  struct addrinfo hints = {
    .ai_flags = AI_V4MAPPED | AI_ADDRCONFIG | AI_NUMERICSERV | AI_PASSIVE,
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
    abort();
  }

  unique_fd sockfd;
  for (struct addrinfo* p = ai; p; p = p->ai_next) {
    sockfd.reset(socket(p->ai_family, p->ai_socktype | SOCK_CLOEXEC, p->ai_protocol));
    if (sockfd == -1) {
      continue;
    }

    int enable = 1;
    if (setsockopt(sockfd.get(), SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) == -1) {
      ERROR("Failed to setsockopt(SO_REUSEADDR): {}", strerror(errno));
      abort();
    }

    if (setsockopt(sockfd.get(), SOL_SOCKET, SO_REUSEPORT, &enable, sizeof(enable)) == -1) {
      ERROR("Failed to setsockopt(SO_REUSEPORT): {}", strerror(errno));
      abort();
    }

    if (bind(sockfd.get(), p->ai_addr, p->ai_addrlen) != -1) {
      break;
    }
  }

  if (sockfd == -1) {
    ERROR("Failed to bind to '{}'", host);
    abort();
  }

  if (fcntl(sockfd.get(), F_SETFL, O_NONBLOCK) != 0) {
    ERROR("Failed to make socket nonblocking: {}", strerror(errno));
    abort();
  }

  if (listen(sockfd.get(), 128) != 0) {
    ERROR("Failed to listen on {}:{}: {}", host, port, strerror(errno));
    abort();
  }

  return sockfd;
}

static unique_fd accept_client(borrowed_fd sockfd) {
  struct sockaddr_storage addr;
  socklen_t addrlen = sizeof(addr);

  unique_fd client_fd(
    TEMP_FAILURE_RETRY(accept4(sockfd.get(), reinterpret_cast<struct sockaddr*>(&addr), &addrlen,
                               SOCK_NONBLOCK | SOCK_CLOEXEC)));

  static_assert(INET6_ADDRSTRLEN > INET_ADDRSTRLEN);
  char s[INET6_ADDRSTRLEN] = {};

  if (addr.ss_family == AF_INET) {
    inet_ntop(AF_INET, &reinterpret_cast<struct sockaddr_in*>(&addr)->sin_addr, s, INET_ADDRSTRLEN);
  } else if (addr.ss_family == AF_INET6) {
    inet_ntop(AF_INET6, &reinterpret_cast<struct sockaddr_in6*>(&addr)->sin6_addr, s,
              INET6_ADDRSTRLEN);
  } else {
    ERROR("Unexpected sockaddr family: {}", addr.ss_family);
    abort();
  }

  INFO("Received client connection from {} (fd = {})", s, client_fd.get());
  return client_fd;
}

struct ClientConnection : public Connection, UpdateServer {
 private:
  ClientConnection(borrowed_fd epollfd, unique_fd fd, GenerationCache& cache,
                   UpdateEngine& update_engine)
      : Connection(epollfd, std::move(fd)), cache_(cache), update_engine_(update_engine) {}

 public:
  ~ClientConnection() { update_engine_.unregister_connection(update_handle_); }

  static std::shared_ptr<ClientConnection> construct(borrowed_fd epollfd, unique_fd fd,
                                                     GenerationCache& cache,
                                                     UpdateEngine& update_engine) {
    std::shared_ptr<ClientConnection> result(
      new ClientConnection(epollfd, std::move(fd), cache, update_engine));
    result->update_handle_ = update_engine.register_connection(result);
    return result;
  }

 private:
  void send_hello() {
    Block buf(sizeof(ServerHello));
    auto hello = reinterpret_cast<ServerHello*>(buf.data());
    hello->selected_checksum = ChecksumAlgorithm::TimestampAndSize;
    this->write(CommandType::ServerHello, std::move(buf));
  }

  void send_die(const std::string& message) {
    Block buf(sizeof(ServerDie) + message.size());
    auto die = reinterpret_cast<ServerDie*>(buf.data());
    die->message_length = message.size();
    memcpy(die->message, message.data(), message.size());
    this->write(CommandType::ServerDie, std::move(buf));
  }

  bool handle_hello(Block& data) {
    auto p = packet_cast<ClientHello>(data);
    if (!p) {
      return false;
    }

    absl::Span<ChecksumAlgorithm> checksums(p->available_checksums, p->checksum_count);
    INFO("Received ClientHello: version={}, eager={}, checksums={}",
         static_cast<uint8_t>(p->version), static_cast<bool>(p->eager), fmt::join(checksums, ","));

    if (p->version != SRYNC_PROTOCOL_VERSION) {
      std::string message =
        fmt::format("Unexpected client protocol version {} (server version = {})",
                    static_cast<uint8_t>(p->version), SRYNC_PROTOCOL_VERSION);
      ERROR(message);
      send_die(message);
      return true;
    }

    send_hello();
    active_ = true;

    return true;
  }

  bool handle_file_versions(Block& data) {
    auto p = packet_cast<ReportFileVersions>(data);
    if (!p) {
      return false;
    }

    INFO("Received ReportFileVersions: id={} count={}", p->file_id, p->checksum_count);
    auto it = remote_files_.find(p->file_id);
    if (it == remote_files_.end()) {
      ERROR("Couldn't find file id {} reported by client", p->file_id);
      return false;
    }

    it->second.acknowledged = true;
    for (size_t i = 0; i < p->checksum_count; ++i) {
      it->second.generations.insert(p->checksums[i]);
    }
    return handle_update(p->file_id);
  }

  bool handle_set_update_priority(Block& data) {
    auto p = packet_cast<SetUpdatePriority>(data);
    if (!p) {
      return false;
    }

    INFO("Received SetUpdatePriority: id={} priority={}", p->update_id, p->priority);
    update_engine_.set_update_priority(update_handle_, p->update_id, p->priority);
    return true;
  }

  bool process_read(const PacketHeader& header, Block data) override final {
    switch (header.type) {
      case CommandType::ClientHello:
        return handle_hello(data);
      case CommandType::ReportFileVersions:
        return handle_file_versions(data);
      case CommandType::SetUpdatePriority:
        return handle_set_update_priority(data);
      default: {
        std::string message = fmt::format("Unhandled packet type: {}", header.type);
        send_die(message);
        WARN(message);
        return true;
      }
    }
    return true;
  }

  bool handle_update(FileId id) {
    auto filename = cache_.filename(id);
    if (!filename) {
      ERROR("Failed to find file to update: id={}", id);
      return false;
    }

    INFO("Processing update for {}, client fd={}", *filename, fd_.get());
    if (!remote_files_[id].advertised) {
      // We haven't told the other end about our file yet.
      remote_files_[id].advertised = true;

      INFO("Advertising {}, client fd={}", *filename, fd_.get());
      Block buf(sizeof(AddFile) + filename->size());
      auto p = reinterpret_cast<AddFile*>(buf.data());
      p->file_id = id;
      p->filename_length = filename->size();
      memcpy(p->filename, filename->data(), filename->size());
      this->write(CommandType::AddFile, std::move(buf));
      return true;
    }

    if (!remote_files_[id].acknowledged) {
      return true;
    }

    return start_update(id);
  }

  bool start_update(FileId id) {
    absl::ReleasableMutexLock lock(&cache_.files_mutex_);
    auto file_it = cache_.files_.find(id);
    if (file_it == cache_.files_.end()) {
      ERROR("Failed to find file to update: id={}", id);
      return false;
    }

    const std::string& filename = file_it->second.filename;
    if (!file_it->second.latest) {
      WARN("Updating file {} which doesn't have a latest checksum (deleted?)", filename);
      return false;
    }

    Checksum checksum = *file_it->second.latest;
    auto gen_it = file_it->second.generations.find(checksum);
    if (gen_it == file_it->second.generations.end()) {
      ERROR("Updated file generation is missing");
      return false;
    }

    // TODO: Check the remote's generations.
    if (remote_files_[id].generations.contains(checksum)) {
      // TODO: Do a rebase.
      INFO("Client has {} generation {}, but we don't know how to use it yet...", filename,
           checksum.str());
    }

    if (remote_files_[id].current_generation == checksum) {
      INFO("Client is already on {}, generation {}", id, checksum.str());
      return true;
    }
    remote_files_[id].current_generation = checksum;
    lock.Release();

    // TODO: Find a shared checksum.
    std::optional<Checksum> base_checksum;
    update_engine_.request_update(update_handle_, id, base_checksum, checksum);
    return true;
  }

  void on_update_begin(UpdateId update_id, FileId file_id, UpdateType update_type,
                       CompressionType compression_type, uint64_t size, int64_t mtime,
                       Checksum old_checksum, Checksum new_checksum) override final {
    Block buf(sizeof(BeginFileUpdate));
    auto p = reinterpret_cast<BeginFileUpdate*>(buf.data());
    p->update_id = update_id;
    p->file_id = file_id;
    p->update_type = update_type;
    p->compression_type = compression_type;
    p->size = size;
    p->mtime = mtime;
    p->old_checksum = old_checksum;
    p->new_checksum = new_checksum;
    write(CommandType::BeginFileUpdate, std::move(buf));
  }

  void on_update(UpdateId update_id,
                 std::function<ssize_t(void*, size_t)> populate_function) override final {
    constexpr size_t buf_size = 256 * 1024;
    Block buf(sizeof(FileUpdate) + buf_size);

    auto p = reinterpret_cast<FileUpdate*>(buf.data());
    p->update_id = update_id;
    ssize_t rc = populate_function(p->data, buf_size);
    if (rc == -1) {
      send_die(fmt::format("Failed to read file while sending update: {}", strerror(errno)));
      return;
    }

    p->data_length = rc;
    buf.resize(sizeof(FileUpdate) + rc);
    DEBUG("Sending {} bytes in update {}", rc, update_id);
    write(CommandType::FileUpdate, std::move(buf));
  }

  void on_update_end(UpdateId update_id, bool success) override final {
    INFO("Finishing update {}", update_id);
    Block buf(sizeof(EndFileUpdate));
    auto p = reinterpret_cast<EndFileUpdate*>(buf.data());
    p->update_id = update_id;
    p->success = success;
    p->padding = 0;
    write(CommandType::EndFileUpdate, std::move(buf));
  }

  bool ready_for_update_data() override final {
    // TODO: Make configurable.
    return bytes_queued() < 8 * 1024 * 1024;
  }

 public:
  bool update_files(const std::vector<FileId>& changed_files) {
    if (!active_) return true;

    if (!advertised_) {
      // If we haven't sent anything yet, advertise all of the files.
      for (auto id : cache_.ids()) {
        if (!handle_update(id)) {
          return false;
        }
      }
      advertised_ = true;
      update_engine_.start(update_handle_);
    } else {
      // Otherwise, advertise only the ones that have changed.
      for (auto id : changed_files) {
        if (!handle_update(id)) {
          return false;
        }
      }
    }

    return true;
  }

  bool flush_updates() {
    update_engine_.check_flush(update_handle_);
    return true;
  }

 private:
  struct RemoteFile {
    absl::flat_hash_set<Checksum> generations;

    std::optional<Checksum> current_generation;

    // Does the client know that the file exists?
    bool advertised = false;

    // Has the client sent us their generations?
    bool acknowledged = false;
  };

  absl::flat_hash_map<FileId, RemoteFile> remote_files_;
  GenerationCache& cache_;
  UpdateEngine& update_engine_;
  UpdateHandle update_handle_;

  bool active_ = false;
  bool advertised_ = false;
};

int server_main(std::string host, int port, std::vector<std::filesystem::path> local_paths) {
  INFO("srync server v" SRYNC_VERSION " starting...");
  unique_fd epfd(epoll_create1(EPOLL_CLOEXEC));
  if (epfd == -1) {
    ERROR("Failed to create epoll fd: {}", strerror(errno));
    abort();
  }

  // listen_socket always succeeds or exits.
  unique_fd sockfd = listen_socket(host, port);
  INFO("Successfully listened on {}:{}", host, port);

  if (!getenv("HOME")) {
    ERROR("$HOME is unset");
    abort();
  }
  std::filesystem::path cachedir = fmt::format("{}/.srync/server", getenv("HOME"));
  GenerationCache cache(std::move(cachedir), ChecksumAlgorithm::TimestampAndSize);
  if (!cache.init()) {
    ERROR("Failed to initialize generation cache, exiting");
    abort();
  }

  UpdateEngine update_engine(cache);

  FileMonitor file_monitor;
  absl::flat_hash_map<FileId, std::filesystem::path> monitored_paths;
  std::vector<FileId> changed_files;

  FileId avail_id = 0;
  for (auto& path : local_paths) {
    FileId id = avail_id++;
    file_monitor.add_watch(path, id);
    cache.register_file(id, path.filename());

    monitored_paths[id] = path;
    changed_files.push_back(id);

    INFO("File {} => {}", id, path.c_str());
  }

  {
    struct epoll_event event;
    event.events = EPOLLIN;
    event.data.fd = sockfd.get();
    if (epoll_ctl(epfd.get(), EPOLL_CTL_ADD, sockfd.get(), &event) != 0) {
      ERROR("epoll_ctl failed to add listen socket: {}", strerror(errno));
      abort();
    }

    event.data.fd = file_monitor.pollfd().get();
    if (epoll_ctl(epfd.get(), EPOLL_CTL_ADD, file_monitor.pollfd().get(), &event) != 0) {
      ERROR("epoll_ctl failed to add inotify fd: {}", strerror(errno));
      abort();
    }
  }

  absl::flat_hash_map<borrowed_fd, std::shared_ptr<ClientConnection>> clients;
  while (true) {
    for (FileId changed_file : changed_files) {
      cache.update_file(changed_file, monitored_paths[changed_file]);
    }
    for (auto& [_, connection] : clients) {
      connection->update_files(changed_files);
    }
    changed_files.clear();

    std::array<struct epoll_event, 8> events;
    int rc = TEMP_FAILURE_RETRY(epoll_wait(epfd.get(), events.data(), events.size(), -1));
    if (rc == -1) {
      ERROR("epoll_wait failed: {}", strerror(errno));
      abort();
    }

    for (size_t i = 0; i < static_cast<size_t>(rc); ++i) {
      struct epoll_event* event = &events[i];
      if (event->data.fd == file_monitor.pollfd().get()) {
        file_monitor.check(&changed_files);
        continue;
      } else if (event->data.fd == sockfd.get()) {
        unique_fd client_fd = accept_client(sockfd);
        INFO("Accepted new client: {}", client_fd.get());
        int client_fd_raw = client_fd.get();
        auto connection =
          ClientConnection::construct(epfd, std::move(client_fd), cache, update_engine);
        clients.emplace(client_fd_raw, std::move(connection));
        continue;
      }

      auto it = clients.find(event->data.fd);
      if (it != clients.end()) {
        bool terminate = false;
        if (!it->second->process_events(event->events)) {
          WARN("Terminating client connection: process_events returned failure (fd={})",
               static_cast<int>(event->data.fd));
          terminate = true;
        } else if (!it->second->flush_updates()) {
          WARN("Terminating client connection: flush_updates returned failure (fd={})",
               static_cast<int>(event->data.fd));
          terminate = true;
        }
        if (terminate) {
          clients.erase(it);
        }
        continue;
      }

      ERROR("Unknown epoll event: {}", static_cast<int>(event->data.fd));
      abort();
    }
  }

  sleep(100);
  return 0;
}
