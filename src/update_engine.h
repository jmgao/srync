#pragma once

#include "protocol.h"

#include <errno.h>
#include <string.h>

#include <memory>
#include <optional>
#include <thread>

#include <absl/synchronization/mutex.h>

#include "srync.h"

struct ClientUpdate {
  std::weak_ptr<Connection> connection_;
};

struct UpdateServer {
  virtual ~UpdateServer() = default;

  virtual void on_update_begin(UpdateId update_id, FileId file_id, UpdateType update_type,
                               CompressionType compression_type, uint64_t size, int64_t mtime,
                               Checksum old_checksum, Checksum new_checksum) = 0;

  virtual void on_update(UpdateId update_id,
                         std::function<ssize_t(void*, size_t)> populate_function) = 0;

  virtual void on_update_end(UpdateId update_id, bool success) = 0;

  // Returns whether we should keep sending more data packets.
  virtual bool ready_for_update_data() = 0;
};

using UpdateHandle = uint64_t;
struct UpdateEngine;
struct UpdateState {
  explicit UpdateState(GenerationCache& cache, UpdateEngine& engine,
                       std::weak_ptr<UpdateServer> connection)
      : cache_(cache), engine_(engine), connection_(connection) {}

  ~UpdateState() {
    absl::MutexLock lock(&mutex_);
    kill_ = true;
  }

  void start() {
    worker_ = std::thread([this]() { this->worker(); });
  }

  void stop() {
    {
      absl::MutexLock lock(&mutex_);
      kill_ = true;
    }

    worker_.join();
  }

 private:
  void worker() {
    auto pred = +[](UpdateState* self) {
      self->mutex_.AssertHeld();
      return self->kill_ || (!self->updates_.empty() && self->ready_for_data_);
    };

    while (true) {
      absl::MutexLock lock(&mutex_, absl::Condition(pred, this));
      if (kill_) {
        return;
      }

      auto connection = connection_.lock();
      if (!connection) {
        ERROR("Connection was destroyed");
        return;
      }

      if (!connection->ready_for_update_data()) {
        ready_for_data_ = false;
        continue;
      }

      UpdateId update_id = prioritized_update();
      auto it = updates_.find(update_id);
      if (it == updates_.end()) {
        ERROR("Failed to find prioritized update");
        abort();
      }

      while (true) {
        // TODO: Keep track of the expected size so we don't need to copy into a temporary buffer
        //       to be able to detect EOF.
        Block buffer(256 * 1024);
        ssize_t rc = TEMP_FAILURE_RETRY(read(it->second.fd.get(), buffer.data(), buffer.size()));
        if (rc == 0) {
          connection->on_update_end(update_id, true);
          delete_update(update_id);
          break;
        } else if (rc == -1) {
          ERROR("read failed when building update: {}", strerror(errno));
          abort();
        }

        connection->on_update(update_id, [&buffer, rc](void* buf, size_t len) -> ssize_t {
          memcpy(buf, buffer.data(), rc);
          return rc;
        });

        if (!connection->ready_for_update_data()) {
          ready_for_data_ = false;
          break;
        }
      }
    }
  }

  UpdateId prioritized_update() ABSL_EXCLUSIVE_LOCKS_REQUIRED(mutex_) {
    if (updates_.empty()) {
      ERROR("prioritized_update called with no updates");
      abort();
    }
    auto& priority_updates = priorities_.begin()->second;
    if (priority_updates.empty()) {
      ERROR("Priority level with no updates");
      abort();
    }
    return *priority_updates.begin();
  }

  void remove_priority(UpdateId id, PriorityLevel priority) ABSL_EXCLUSIVE_LOCKS_REQUIRED(mutex_) {
    auto priority_level_it = priorities_.find(priority);
    if (priority_level_it == priorities_.end()) {
      ERROR("Update's priority level is missing");
      abort();
    }

    auto priority_it = priority_level_it->second.find(id);
    if (priority_it == priority_level_it->second.end()) {
      ERROR("Update is missing from its priority");
      abort();
    }
    priority_level_it->second.erase(priority_it);
    if (priority_level_it->second.empty()) {
      priorities_.erase(priority_level_it);
    }
  }

 public:
  bool request_update(UpdateId update_id, FileId file_id, std::optional<Checksum> old_checksum,
                      Checksum new_checksum) {
    auto connection = connection_.lock();
    if (!connection) {
      ERROR("Connection was destroyed");
      return false;
    }

    unique_fd target_file = cache_.open_file_version(file_id, new_checksum);
    if (target_file == -1) {
      ERROR("Failed to open file {} generation {}: {}", file_id, new_checksum.str(),
            strerror(errno));
      return false;
    }

    Checksum empty = {};
    connection->on_update_begin(update_id, file_id, UpdateType::FullTransfer, CompressionType::None,
                                new_checksum.value.timestamp_and_size.size,
                                new_checksum.value.timestamp_and_size.timestamp, empty,
                                new_checksum);

    absl::MutexLock lock(&mutex_);
    updates_[update_id].fd = std::move(target_file);
    priorities_[DEFAULT_PRIORITY_LEVEL].insert(update_id);

    return true;
  }

  void set_priority(UpdateId id, PriorityLevel priority) {
    absl::MutexLock lock(&mutex_);
    auto it = updates_.find(id);
    if (it == updates_.end()) {
      WARN("Failed to find update {} (perhaps finished?)", id);
      return;
    }

    if (priority == it->second.priority) {
      return;
    }

    remove_priority(id, it->second.priority);
    it->second.priority = priority;
    priorities_[priority].insert(id);
  }

  void check_flush() {
    absl::MutexLock lock(&mutex_);
    ready_for_data_ = true;
  }

 private:
  void delete_update(UpdateId id) ABSL_EXCLUSIVE_LOCKS_REQUIRED(mutex_) {
    auto it = updates_.find(id);
    if (it == updates_.end()) {
      ERROR("Failed to find update {}", id);
      abort();
    }

    remove_priority(id, it->second.priority);
    updates_.erase(it);
  }

  GenerationCache& cache_;
  [[maybe_unused]] UpdateEngine& engine_;

  absl::Mutex mutex_;
  bool kill_ ABSL_GUARDED_BY(mutex_) = false;
  bool ready_for_data_ ABSL_GUARDED_BY(mutex_) = true;

  struct ClientUpdate {
    unique_fd fd;
    PriorityLevel priority = DEFAULT_PRIORITY_LEVEL;
  };

  absl::btree_map<PriorityLevel, absl::btree_set<UpdateId>> priorities_ ABSL_GUARDED_BY(mutex_);
  absl::btree_map<UpdateId, ClientUpdate> updates_ ABSL_GUARDED_BY(mutex_);

  std::weak_ptr<UpdateServer> connection_;
  std::thread worker_;
};

struct UpdateEngine {
  explicit UpdateEngine(GenerationCache& cache) : cache_(cache) {}

  // TODO: Scan for dead weak_ptrs.
  UpdateHandle register_connection(std::weak_ptr<UpdateServer> connection) {
    auto update_state = std::make_shared<UpdateState>(cache_, *this, connection);

    absl::MutexLock lock(&connections_mutex_);
    auto handle = next_update_handle_++;
    connections_[handle] = std::move(update_state);
    return handle;
  }

  std::shared_ptr<UpdateState> get_state(UpdateHandle handle) {
    absl::MutexLock lock(&connections_mutex_);
    auto it = connections_.find(handle);
    if (it == connections_.end()) {
      return nullptr;
    }

    // TODO: Check if the connection is dead?
    return it->second;
  }

  void start(UpdateHandle handle) {
    auto update_state = get_state(handle);
    if (!update_state) {
      ERROR("Attempted to start unknown UpdateHandle");
      abort();
    }

    update_state->start();
  }

  void unregister_connection(UpdateHandle handle) {
    auto update_state = get_state(handle);
    if (!update_state) {
      ERROR("Attempted to unregister unknown UpdateHandle");
      abort();
    }

    update_state->stop();

    absl::MutexLock lock(&connections_mutex_);
    auto it = connections_.find(handle);
    if (it == connections_.end()) {
      ERROR("Failed to find UpdateHandle when unregistering");
      abort();
    }
    connections_.erase(it);
  }

  UpdateId request_update(UpdateHandle handle, FileId file_id, std::optional<Checksum> old_checksum,
                          Checksum new_checksum) {
    auto update_state = get_state(handle);
    if (!update_state) {
      ERROR("Attempted to request update on unknown UpdateHandle");
      abort();
    }

    INFO("Starting update of file {} to generation {}", file_id, new_checksum.str());

    // TODO: Updates should probably be generated centrally, instead of for each connection.
    UpdateId update_id = next_update_id_.fetch_add(1);
    update_state->request_update(update_id, file_id, old_checksum, new_checksum);
    return update_id;
  }

  void set_update_priority(UpdateHandle handle, UpdateId id, PriorityLevel priority) {
    auto update_state = get_state(handle);
    if (!update_state) {
      ERROR("Attempted to set priority on unknown UpdateHandle");
      abort();
    }

    INFO("Setting priority of update {} to {}", id, priority);
    update_state->set_priority(id, priority);
  }

  void check_flush(UpdateHandle handle) {
    auto update_state = get_state(handle);
    if (!update_state) {
      ERROR("Attempted to check flush on unknown UpdateHandle");
      abort();
    }
    update_state->check_flush();
  }

  GenerationCache& cache_;

  absl::Mutex connections_mutex_;
  UpdateHandle next_update_handle_ ABSL_GUARDED_BY(connections_mutex_) = 1000;

  absl::flat_hash_map<UpdateHandle, std::shared_ptr<UpdateState>> connections_
    ABSL_GUARDED_BY(connections_mutex_);
  std::atomic<UpdateId> next_update_id_ = 2000;
};
