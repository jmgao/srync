#pragma once

#include <stdint.h>

#include <atomic>
#include <filesystem>
#include <memory>
#include <vector>

#include <absl/base/thread_annotations.h>
#include <absl/container/btree_map.h>
#include <absl/container/flat_hash_map.h>
#include <absl/synchronization/mutex.h>

#define FUSE_USE_VERSION 34
#include <fuse_lowlevel.h>

using Ino = uint64_t;

enum class InodeType {
  Directory,
  File,
};

struct Directory;
struct File;

struct Inode : public std::enable_shared_from_this<Inode> {
 protected:
  Inode(InodeType type, Ino ino, std::string name);

 public:
  virtual ~Inode() = default;

  Inode(const Inode& copy) = delete;
  Inode(Inode&& move) = delete;
  Inode& operator=(const Inode& copy) = delete;
  Inode& operator=(Inode&& move) = delete;

  Directory* as_dir();
  const Directory* as_dir() const;

  File* as_file();
  const File* as_file() const;

  virtual void stat(struct stat* st, double* timeout) const;

  const InodeType type_;
  const Ino ino_;
  const std::string name_;
};

struct OpenDir {
  OpenDir(Ino parent, std::vector<Ino> children) : parent(parent), children(std::move(children)) {}

  const Ino parent;
  const std::vector<Ino> children;
};

struct Directory : public Inode {
  Directory(Ino ino, std::string name, Ino parent);
  virtual ~Directory() = default;

  void add_child(const std::string& name, Ino ino);

  std::unique_ptr<OpenDir> open();

  virtual void stat(struct stat* st, double* timeout) const override final;

  const Ino parent_;

  mutable absl::Mutex dir_mutex_;
  absl::btree_map<std::string, Ino> children_ ABSL_GUARDED_BY(dir_mutex_);
};

struct File;

struct OpenFile {
  explicit OpenFile(std::shared_ptr<File> file) : file(file) {}
  const std::shared_ptr<File> file;
};

struct FileProvider {
  virtual ~FileProvider() = default;
  virtual void read(fuse_req_t req, uint64_t size, uint64_t offset) = 0;
};

struct File : public Inode {
  File(Ino ino, std::string name, uint64_t mtime, uint64_t size,
       std::shared_ptr<FileProvider> provider);
  virtual ~File() = default;

  std::unique_ptr<OpenFile> open();

  virtual void stat(struct stat* st, double* timeout) const override final;
  void read(fuse_req_t req, uint64_t size, uint64_t offset);

  const uint64_t mtime_;
  const uint64_t size_;
  const std::shared_ptr<FileProvider> provider_;
};

struct Fs {
  Fs();
  ~Fs();

  static Fs* from(fuse_req_t req) { return static_cast<Fs*>(fuse_req_userdata(req)); }

  void add_file(std::string filename, uint64_t mtime, uint64_t size,
                std::shared_ptr<FileProvider> provider);
  bool mount(const std::filesystem::path& path);
  void run();

  Ino next_ino();
  std::shared_ptr<Inode> lookup(fuse_ino_t ino) const;
  void readdir(fuse_req_t req, fuse_ino_t ino, size_t size, off_t offset, struct fuse_file_info* fi,
               bool plus) const;

  static void fs_init(void* userdata, struct fuse_conn_info* conn);
  static void fs_destroy(void* userdata);
  static void fs_lookup(fuse_req_t req, fuse_ino_t parent, const char* name);
  static void fs_getattr(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info* fi);
  static void fs_opendir(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info* fi);
  static void fs_readdir(fuse_req_t req, fuse_ino_t ino, size_t size, off_t offset,
                         struct fuse_file_info* fi);
  static void fs_releasedir(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info* fi);
  static void fs_readdirplus(fuse_req_t req, fuse_ino_t ino, size_t size, off_t offset,
                             struct fuse_file_info* fi);
  static void fs_open(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info* fi);
  static void fs_release(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info* fi);
  static void fs_read(fuse_req_t req, fuse_ino_t ino, size_t size, off_t offset,
                      struct fuse_file_info* fi);
  static void fs_statfs(fuse_req_t req, fuse_ino_t ino);

  static constexpr size_t BLOCK_SIZE = 4096;

 private:
  fuse_session* session_ = nullptr;

  std::atomic<uint64_t> next_ino_ = 1;
  std::shared_ptr<Directory> root_;

  mutable absl::Mutex inode_mutex_;
  absl::flat_hash_map<Ino, std::shared_ptr<Inode>> inodes_ ABSL_GUARDED_BY(inode_mutex_);
};
