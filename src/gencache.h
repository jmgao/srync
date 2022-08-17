#include <filesystem>

#include <dirent.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <sys/inotify.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <absl/container/flat_hash_map.h>
#include <absl/container/flat_hash_set.h>
#include <absl/synchronization/mutex.h>

#include "protocol.h"
#include "srync.h"

using FileId = uint16_t;

// If we monitor files directly with inotify, we won't notice files that are linked/renamed
// into place, so we need to watch the parent directory for changes.
struct FileMonitor {
  FileMonitor() {
    infd_.reset(inotify_init1(IN_NONBLOCK | IN_CLOEXEC));
    if (infd_ == -1) {
      ERROR("Failed to create inotify fd: {}", strerror(errno));
      exit(1);
    }
  }

  void add_watch(const std::filesystem::path& path, FileId id) {
    auto absolute_path = std::filesystem::absolute(path);
    std::string filename = absolute_path.filename();
    std::string parent = absolute_path.parent_path();

    int wd = inotify_add_watch(infd_.get(), parent.c_str(),
                               IN_CREATE | IN_MOVED_TO | IN_MOVED_FROM | IN_CLOSE_WRITE |
                                 IN_DELETE | IN_ONLYDIR | IN_EXCL_UNLINK);

    if (wd == -1) {
      ERROR("Failed to register inotify watch on '{}': {}", parent.c_str(), strerror(errno));
      exit(1);
    }
    watched_dirs_[wd][std::move(filename)] = id;
  }

  void check(std::vector<FileId>* observed_changes) {
    observed_changes->clear();
    while (true) {
      union {
        struct inotify_event event;
        char bytes[sizeof(struct inotify_event) + NAME_MAX + 1];
      } buf;

      int rc = read(infd_.get(), &buf, sizeof(buf));
      if (rc == -1) {
        if (errno == EAGAIN) {
          break;
        }
        ERROR("inotify read failed: {}", strerror(errno));
        exit(1);
      }

      auto dir_it = watched_dirs_.find(buf.event.wd);
      if (dir_it == watched_dirs_.end()) {
        ERROR("Unknown inotify watch descriptor: {}", buf.event.wd);
        exit(1);
      }

      if (buf.event.mask & IN_IGNORED) {
        // TODO: Handle this sanely.
        ERROR("Watched directory was deleted");
        exit(1);
      }

      std::string filename = buf.event.name;
      auto file_it = dir_it->second.find(filename);
      if (file_it != dir_it->second.end()) {
        FileId id = file_it->second;
        observed_changes->push_back(id);

        if (buf.event.mask & IN_CREATE) {
          INFO("Monitored file {} was created", id);
        }
        if (buf.event.mask & IN_MOVED_TO) {
          INFO("Monitored file {} was moved in", id);
        }
        if (buf.event.mask & IN_CLOSE_WRITE) {
          INFO("Monitored file {} was closed in write mode", id);
        }

        if (buf.event.mask & IN_DELETE) {
          INFO("Monitored file {} was deleted", id);
        }
        if (buf.event.mask & IN_MOVED_FROM) {
          INFO("Monitored file {} was moved out", id);
        }
      }
    }
  }

  borrowed_fd pollfd() { return infd_; }

 private:
  unique_fd infd_;
  absl::flat_hash_map<int, absl::flat_hash_map<std::string, FileId>> watched_dirs_;
};

struct FileGeneration {
  uint64_t size;
  int64_t mtime;
  Checksum checksum;
};

struct GenerationCache {
  GenerationCache(std::filesystem::path directory, ChecksumAlgorithm checksum_algo)
      : checksum_algo_(checksum_algo), directory_(std::move(directory)) {}

  bool init() {
    if (!std::filesystem::is_directory(directory_) &&
        !std::filesystem::create_directories(directory_)) {
      ERROR("Failed to create generation cache directory '{}': {}", directory_.c_str(),
            strerror(errno));
      return false;
    }

    dirfd_.reset(open(directory_.c_str(), O_RDONLY | O_CLOEXEC | O_DIRECTORY));
    if (dirfd_.get() == -1) {
      ERROR("Failed to open generation cache directory '{}': {}", directory_.c_str(),
            strerror(errno));
      return false;
    }

    return true;
  }

  bool register_file(FileId id, std::string filename) {
    if (mkdirat(dirfd_.get(), filename.c_str(), 0700) != 0 && errno != EEXIST) {
      ERROR("Failed to create cache directory '{}/{}': {}", directory_.c_str(), filename,
            strerror(errno));
      return false;
    }

    unique_fd subdir_fd(openat(dirfd_.get(), filename.c_str(), O_RDONLY | O_CLOEXEC | O_DIRECTORY));
    if (subdir_fd == -1) {
      ERROR("Failed to open cache directory: '{}/{}': {}", directory_.c_str(), filename,
            strerror(errno));
      return false;
    }

    // Scan for existing generations.
    int dupfd = fcntl(subdir_fd.get(), F_DUPFD_CLOEXEC, 0);
    DIR* subdir = fdopendir(dupfd);
    if (!subdir) {
      ERROR("Failed to open cache directory from fd: {}", strerror(errno));
      return false;
    }
    while (struct dirent* dirent = readdir(subdir)) {
      if (dirent->d_type != DT_REG) {
        continue;
      }
    }
    closedir(subdir);

    absl::MutexLock lock(&files_mutex_);
    files_[id] = {
      .filename = std::move(filename),
      .cache_directory = std::move(subdir_fd),
    };
    return true;
  }

  bool calculate_checksum(Checksum* out_checksum, borrowed_fd fd) {
    struct stat st;
    if (fstat(fd.get(), &st) != 0) {
      ERROR("Failed to fstat file to calculate checksum: {}", strerror(errno));
      return false;
    }

    memset(out_checksum, 0, sizeof(*out_checksum));
    out_checksum->type = ChecksumAlgorithm::TimestampAndSize;
    out_checksum->value.timestamp_and_size.timestamp = st.st_mtim.tv_sec;
    out_checksum->value.timestamp_and_size.size = st.st_size;
    return true;
  }

  unique_fd open_tmpfile() const {
    unique_fd tmpfile(openat(AT_FDCWD, directory_.c_str(), O_TMPFILE | O_RDWR | O_CLOEXEC, 0700));
    if (tmpfile == -1) {
      ERROR("Failed to create temporary file: {}", strerror(errno));
      return {};
    }
    return tmpfile;
  }

  bool add_version_locked(FileId id, Checksum checksum, uint64_t size, int64_t mtime,
                          borrowed_fd fd, bool overwrite = false)
    ABSL_EXCLUSIVE_LOCKS_REQUIRED(files_mutex_) {
    auto it = files_.find(id);
    if (it == files_.end()) {
      ERROR("Failed to find filename for file {}", id);
      return {};
    }

    FileGeneration gen = {
      .size = size,
      .mtime = mtime,
      .checksum = checksum,
    };
    std::string checksum_str = checksum.str();
    INFO("Calculated checksum for updated file {}: {}", id, checksum_str);
    std::filesystem::path cache_path = fmt::format(
      "{}/{}/{}", directory_.c_str(), it->second.filename.c_str(), checksum_str.c_str());

    borrowed_fd cache_dir = it->second.cache_directory;
    if (faccessat(cache_dir.get(), checksum_str.c_str(), F_OK, 0) == 0) {
      // TODO: Verify its checksum, once we actually start using real checksums?
      if (!overwrite) {
        INFO("Cached file already exists: {}", cache_path.c_str());
        it->second.latest = checksum;
        it->second.generations[checksum] = gen;
        return true;
      } else {
        INFO("Cached file already exists, unlinking: {}", cache_path.c_str());
        if (unlinkat(cache_dir.get(), checksum_str.c_str(), 0) != 0) {
          ERROR("Failed to unlink cached file: {}", strerror(errno));
          return false;
        }
      }
    }

    if (linkat(AT_FDCWD, fmt::format("/proc/self/fd/{}", fd.get()).c_str(), cache_dir.get(),
               checksum_str.c_str(), AT_SYMLINK_FOLLOW) != 0) {
      ERROR("Failed to link cache file: {}", strerror(errno));
      return false;
    }
    INFO("Created cache file: {}", cache_path.c_str());
    it->second.latest = checksum;
    it->second.generations[checksum] = gen;
    return true;
  }

  bool add_version(FileId id, Checksum checksum, uint64_t size, int64_t mtime, borrowed_fd fd,
                   bool overwrite = false) {
    absl::MutexLock lock(&files_mutex_);
    return add_version_locked(id, checksum, size, mtime, fd, overwrite);
  }

  unique_fd open_file_version_locked(FileId id, Checksum checksum) const
    ABSL_EXCLUSIVE_LOCKS_REQUIRED(files_mutex_) {
    auto it = files_.find(id);
    if (it == files_.end()) {
      ERROR("Failed to find filename for file {}", id);
      return {};
    }
    std::string checksum_str = checksum.str();
    std::string relpath = fmt::format("{}/{}", it->second.filename, checksum.str());
    unique_fd result(openat(dirfd_.get(), relpath.c_str(), O_RDONLY | O_CLOEXEC));
    return result;
  }

  unique_fd open_file_version(FileId id, Checksum checksum) const {
    absl::MutexLock lock(&files_mutex_);
    return open_file_version_locked(id, checksum);
  }

  unique_fd clone_file(uint64_t* out_size, int64_t* out_mtime, const std::filesystem::path& path) {
    // Copy the file into a temporary file, first.
    unique_fd tmpfile = open_tmpfile();
    if (tmpfile == -1) {
      // Error reported by open_tmpfile.
      abort();
    }

    unique_fd updated_file(open(path.c_str(), O_RDONLY | O_CLOEXEC));
    if (updated_file == -1) {
      WARN("Failed to open updated file: {}", strerror(errno));
      return {};
    }

    struct stat st;
    if (fstat(updated_file.get(), &st) != 0) {
      ERROR("fstat failed: {}", strerror(errno));
      return {};
    }

    size_t size = st.st_size;
    INFO("Attempting to clone file...");
    if (ioctl(tmpfile.get(), FICLONE, updated_file.get()) == 0) {
      INFO("File successfully cloned with ioctl(FICLONE)");
    } else {
      INFO("Failed to clone file with ioctl(FICLONE), falling back to copy_file_range: {}",
           strerror(errno));
      bool cfr_works = true;
      while (size > 0) {
        ssize_t rc;
        if (cfr_works) {
          rc = copy_file_range(updated_file.get(), nullptr, tmpfile.get(), nullptr, size, 0);
          if (rc == -1) {
            INFO("copy_file_range failed, falling back to read/write (error was: {})",
                 strerror(errno));
            cfr_works = false;
          }
        } else {
          ERROR("TODO: read/write fallback unimplemented!");
          abort();
        }

        size -= rc;
      }
    }

    struct timespec times[2] = {st.st_mtim, st.st_mtim};
    if (futimens(tmpfile.get(), times) != 0) {
      ERROR("Failed to set temporary file timestamps: {}", strerror(errno));
      abort();
    }
    *out_size = size;
    *out_mtime = st.st_mtim.tv_sec;
    return tmpfile;
  }

  void update_file(FileId id, const std::filesystem::path& path) {
    uint64_t size;
    int64_t mtime;
    unique_fd tmpfile = clone_file(&size, &mtime, path);
    if (tmpfile == -1) {
      INFO("File {} disappeared", path.c_str());
      absl::MutexLock lock(&files_mutex_);
      files_.at(id).latest.reset();
      return;
    }

    Checksum checksum;
    if (!calculate_checksum(&checksum, tmpfile)) {
      abort();
    }

    // Check to see if we already have this generation tracked.
    absl::MutexLock lock(&files_mutex_);
    auto it = files_.find(id);
    if (it == files_.end()) {
      ERROR("Unknown changed file id: {}", id);
      abort();
    }

    if (it->second.generations.contains(checksum)) {
      INFO("File generation already exists");
    } else if (!add_version_locked(id, checksum, size, mtime, std::move(tmpfile))) {
      ERROR("Failed to add file to cache");
      abort();
    }

    INFO("New generation discovered for file {}", path.c_str());
  }

  std::optional<std::string> filename(FileId id) const {
    absl::MutexLock lock(&files_mutex_);
    auto it = files_.find(id);
    if (it == files_.end()) {
      return {};
    }
    return it->second.filename;
  }

  std::vector<FileId> ids() const {
    std::vector<FileId> result;

    absl::MutexLock lock(&files_mutex_);
    for (auto& [id, _] : files_) {
      result.push_back(id);
    }
    return result;
  }

  const ChecksumAlgorithm checksum_algo_;

  const std::filesystem::path directory_;
  unique_fd dirfd_;

  struct FileGeneration {
    uint64_t size;
    int64_t mtime;
    Checksum checksum;
  };

  struct File {
    std::string filename;
    unique_fd cache_directory;
    std::optional<Checksum> latest;
    absl::flat_hash_map<Checksum, FileGeneration> generations;
  };

  mutable absl::Mutex files_mutex_;
  absl::flat_hash_map<FileId, File> files_ ABSL_GUARDED_BY(files_mutex_);
};
