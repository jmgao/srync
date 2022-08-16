#include "fs.h"

#include <string.h>
#include <sys/stat.h>
#include <sys/statvfs.h>

#include <memory>

#include <absl/synchronization/mutex.h>
#include <spdlog/spdlog.h>

#include "srync.h"

static constexpr struct fuse_lowlevel_ops fs_oper = {
  .init = Fs::fs_init,
  .destroy = Fs::fs_destroy,
  .lookup = Fs::fs_lookup,
  .getattr = Fs::fs_getattr,
  .open = Fs::fs_open,
  .read = Fs::fs_read,
  .release = Fs::fs_release,
  .opendir = Fs::fs_opendir,
  .readdir = Fs::fs_readdir,
  .releasedir = Fs::fs_releasedir,
  .statfs = Fs::fs_statfs,
  .readdirplus = Fs::fs_readdirplus,
};

Inode::Inode(InodeType type, Ino ino, std::string name)
    : type_(type), ino_(ino), name_(std::move(name)) {}

Directory* Inode::as_dir() {
  if (type_ == InodeType::Directory) {
    return static_cast<Directory*>(this);
  }
  return nullptr;
}

const Directory* Inode::as_dir() const {
  if (type_ == InodeType::Directory) {
    return static_cast<const Directory*>(this);
  }
  return nullptr;
}

File* Inode::as_file() {
  if (type_ == InodeType::File) {
    return static_cast<File*>(this);
  }
  return nullptr;
}

const File* Inode::as_file() const {
  if (type_ == InodeType::File) {
    return static_cast<const File*>(this);
  }
  return nullptr;
}

void Inode::stat(struct stat* st, double* timeout) const {
  memset(st, 0, sizeof(*st));

  st->st_dev = 0;
  st->st_ino = ino_;
  st->st_mode = 0700;
  st->st_nlink = 1;
  st->st_uid = getuid();
  st->st_gid = getgid();
  st->st_rdev = 0;
  st->st_blksize = Fs::BLOCK_SIZE;
  st->st_blocks = 0;
}

Directory::Directory(Ino ino, std::string name, Ino parent)
    : Inode(InodeType::Directory, ino, std::move(name)), parent_(parent) {}

void Directory::stat(struct stat* st, double* timeout) const {
  Inode::stat(st, timeout);
  st->st_mode |= S_IFDIR;
  st->st_size = 0;
  *timeout = 86400;
}

void Directory::add_child(const std::string& name, Ino ino) {
  absl::MutexLock lock(&dir_mutex_);
  children_[name] = ino;
}

std::unique_ptr<OpenDir> Directory::open() {
  std::vector<Ino> children;
  {
    absl::MutexLock lock(&dir_mutex_);
    for (const auto& [name, child_ino] : children_) {
      children.push_back(child_ino);
    }
  }

  return std::make_unique<OpenDir>(this->parent_, std::move(children));
}

File::File(Ino ino, std::string name, uint64_t mtime, uint64_t size,
           std::shared_ptr<FileProvider> provider)
    : Inode(InodeType::File, ino, std::move(name)),
      mtime_(mtime),
      size_(size),
      provider_(std::move(provider)) {}

void File::stat(struct stat* st, double* timeout) const {
  Inode::stat(st, timeout);
  st->st_mtim.tv_sec = mtime_;
  st->st_ctim.tv_sec = mtime_;
  st->st_mode |= S_IFREG;
  st->st_size = size_;
  st->st_blocks = (size_ + Fs::BLOCK_SIZE - 1) / Fs::BLOCK_SIZE;
  *timeout = 0;
}

std::unique_ptr<OpenFile> File::open() {
  return std::make_unique<OpenFile>(std::static_pointer_cast<File>(shared_from_this()));
}

void File::read(fuse_req_t req, uint64_t size, uint64_t offset) {
  provider_->read(req, size, offset);
}

Fs::Fs() {
  root_ = std::make_shared<Directory>(next_ino(), "<root>", 1);
  inodes_[root_->ino_] = root_;
}

Fs::~Fs() {
  if (session_) {
    fuse_session_unmount(session_);
    fuse_remove_signal_handlers(session_);
    fuse_session_destroy(session_);
  }
}

void Fs::add_file(std::string filename, uint64_t mtime, uint64_t size,
                  std::shared_ptr<FileProvider> provider) {
  Ino ino = this->next_ino();
  auto inode = std::make_shared<File>(ino, std::move(filename), mtime, size, std::move(provider));

  {
    absl::MutexLock lock(&inode_mutex_);
    inodes_[ino] = inode;
  }

  root_->add_child(inode->name_, ino);
}

bool Fs::mount(const std::filesystem::path& path) {
  DEBUG("Fs::mount({})", path.c_str());

  fuse_args args = FUSE_ARGS_INIT(0, nullptr);
  if (fuse_opt_add_arg(&args, "srync") || fuse_opt_add_arg(&args, "-o") ||
      fuse_opt_add_arg(&args, "default_permissions,fsname=srync,ro,noatime")) {
    ERROR("fuse_opt_add_arg failed");
    return false;
  }

  session_ = fuse_session_new(&args, &fs_oper, sizeof(fs_oper), this);
  if (session_ == nullptr) {
    ERROR("fuse_session_failed: {}", strerror(errno));
    return false;
  }

  if (fuse_set_signal_handlers(session_) != 0) {
    ERROR("fuse_set_signal_handlers failed: {}", strerror(errno));
    fuse_session_destroy(session_);
    session_ = nullptr;
    return false;
  }

  if (fuse_session_mount(session_, path.c_str()) != 0) {
    ERROR("fuse_session_mount failed: {}", strerror(errno));
    fuse_remove_signal_handlers(session_);
    fuse_session_destroy(session_);
    session_ = nullptr;
    return false;
  }

  return true;
}

Ino Fs::next_ino() {
  return next_ino_.fetch_add(1);
}

void Fs::run() {
  struct fuse_loop_config loop_config;
  loop_config.clone_fd = 0;
  loop_config.max_idle_threads = 10;
  fuse_session_loop_mt(session_, &loop_config);
}

std::shared_ptr<Inode> Fs::lookup(fuse_ino_t ino) const {
  absl::MutexLock lock(&inode_mutex_);
  auto it = inodes_.find(ino);
  if (it == inodes_.end()) {
    return nullptr;
  }
  return it->second;
}

void Fs::fs_init(void* userdata, struct fuse_conn_info* conn) {
  DEBUG("fs_init");
  if (conn->capable & FUSE_CAP_EXPORT_SUPPORT) {
    conn->want |= FUSE_CAP_EXPORT_SUPPORT;
  }
}

void Fs::fs_destroy(void* userdata) {
  DEBUG("fs_destroy");
}

#define LOOKUP(ino)                                         \
  ({                                                        \
    std::shared_ptr<Inode> x = fs->lookup(ino);             \
    if (!x) {                                               \
      WARN("{}: failed to lookup inode {}", __func__, ino); \
      fuse_reply_err(req, ENOENT);                          \
      return;                                               \
    }                                                       \
    x;                                                      \
  })

void Fs::fs_lookup(fuse_req_t req, fuse_ino_t parent, const char* name) {
  DEBUG("fs_lookup(ino={}, name={})", parent, name);

  Fs* fs = Fs::from(req);
  auto parent_inode = LOOKUP(parent);
  Directory* dir = parent_inode->as_dir();
  if (!dir) {
    WARN("fs_lookup called on non-directory inode {}", parent);
    fuse_reply_err(req, ENOTDIR);
    return;
  }

  Ino child_ino;

  {
    absl::MutexLock lock(&dir->dir_mutex_);
    auto it = dir->children_.find(name);
    if (it == dir->children_.end()) {
      DEBUG("fs_lookup(ino={}, name={}) = ENOENT", parent, name);
      fuse_reply_err(req, ENOENT);
      return;
    }
    child_ino = it->second;
  }

  auto child_inode = LOOKUP(child_ino);
  fuse_entry_param entry = {};
  entry.ino = child_ino;
  entry.generation = 0;
  child_inode->stat(&entry.attr, &entry.attr_timeout);
  entry.entry_timeout = 86400;
  fuse_reply_entry(req, &entry);
}

void Fs::fs_getattr(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info* fi) {
  DEBUG("fs_getattr(ino={})", ino);

  Fs* fs = Fs::from(req);
  auto inode = LOOKUP(ino);

  struct stat st;
  double timeout;
  inode->stat(&st, &timeout);

  DEBUG("fs_getattr(ino={}) = 0", ino);
  fuse_reply_attr(req, &st, timeout);
}

void Fs::fs_opendir(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info* fi) {
  DEBUG("fs_opendir(ino={})", ino);

  Fs* fs = Fs::from(req);
  auto inode = LOOKUP(ino);
  if (Directory* dir = inode->as_dir()) {
    std::unique_ptr<OpenDir> opendir = dir->open();
    fi->fh = reinterpret_cast<uint64_t>(opendir.release());
    DEBUG("fs_opendir(ino={}) = {:#x}", ino, fi->fh);
    fuse_reply_open(req, fi);
  } else {
    WARN("fs_opendir(ino={}) = ENOTDIR", ino);
    fuse_reply_err(req, ENOTDIR);
  }
}

void Fs::fs_releasedir(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info* fi) {
  DEBUG("fs_releasedir(ino={}) = {:#x}", ino, fi->fh);
  OpenDir* opendir = reinterpret_cast<OpenDir*>(fi->fh);
  delete opendir;
  fuse_reply_err(req, 0);
}

void Fs::readdir(fuse_req_t req, fuse_ino_t ino, size_t size, off_t offset,
                 struct fuse_file_info* fi, bool plus) const {
  OpenDir* dir = reinterpret_cast<OpenDir*>(fi->fh);
  auto buf = std::make_unique<char[]>(size);
  char* p = buf.get();
  size_t bytes_written = 0;

  if (offset == 0) {
    offset = 1;
  }

  while (dir->children.size() + 2 >= static_cast<size_t>(offset)) {
    const char* name = nullptr;
    std::shared_ptr<Inode> inode;

    fuse_entry_param entry = {};
    entry.generation = 0;
    entry.entry_timeout = 86400;
    if (offset == 1 || offset == 2) {
      name = offset == 1 ? "." : "..";
      entry.ino = ino;
      entry.attr.st_dev = 0;
      entry.attr.st_ino = offset == 1 ? ino : dir->parent;
      entry.attr.st_mode = S_IFDIR | 0700;
      entry.attr.st_nlink = 1;
      entry.attr.st_uid = getuid();
      entry.attr.st_gid = getgid();
      entry.attr.st_rdev = 0;
      entry.attr.st_size = 0;
      entry.attr.st_blksize = Fs::BLOCK_SIZE;
      entry.attr.st_blocks = 0;
      entry.attr_timeout = 86400;
    } else {
      Ino child_ino = dir->children[offset - 3];
      inode = this->lookup(child_ino);
      if (!inode) {
        WARN("failed to find inode {} (child of {})", child_ino, ino);
        ++offset;
        continue;
      }
      name = inode->name_.c_str();
      entry.ino = child_ino;
      inode->stat(&entry.attr, &entry.attr_timeout);
    }

    size_t rc;
    if (plus) {
      rc = fuse_add_direntry_plus(req, p, size, name, &entry, offset + 1);
    } else {
      rc = fuse_add_direntry(req, p, size, name, &entry.attr, offset + 1);
    }

    if (rc > size) {
      break;
    }

    p += rc;
    size -= rc;
    bytes_written += rc;
    ++offset;
  }

  fuse_reply_buf(req, buf.get(), bytes_written);
}

void Fs::fs_readdir(fuse_req_t req, fuse_ino_t ino, size_t size, off_t offset,
                    struct fuse_file_info* fi) {
  DEBUG("fs_readdir");
  Fs* fs = Fs::from(req);
  fs->readdir(req, ino, size, offset, fi, false);
}

void Fs::fs_readdirplus(fuse_req_t req, fuse_ino_t ino, size_t size, off_t offset,
                        struct fuse_file_info* fi) {
  DEBUG("fs_readdirplus");
  Fs* fs = Fs::from(req);
  fs->readdir(req, ino, size, offset, fi, true);
}

void Fs::fs_open(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info* fi) {
  DEBUG("fs_open");
  Fs* fs = Fs::from(req);
  std::shared_ptr<Inode> inode = LOOKUP(ino);

  // TODO: Check flags? Or does the kernel handle this for us already?
  if (File* f = inode->as_file()) {
    std::unique_ptr<OpenFile> openfile = f->open();
    fi->fh = reinterpret_cast<uint64_t>(openfile.release());
    fi->direct_io = 1;
    DEBUG("fs_openfile(ino={}) = {:#x}", ino, fi->fh);
    fuse_reply_open(req, fi);
  } else {
    fuse_reply_err(req, EISDIR);
  }
}

void Fs::fs_release(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info* fi) {
  DEBUG("fs_release(ino={}) = {:#x}", ino, fi->fh);
  OpenFile* openfile = reinterpret_cast<OpenFile*>(fi->fh);
  delete openfile;
  fuse_reply_err(req, 0);
}

void Fs::fs_read(fuse_req_t req, fuse_ino_t ino, size_t size, off_t offset,
                 struct fuse_file_info* fi) {
  TRACE("fs_read(ino={}, size={}, offset={})", ino, size, offset);
  OpenFile* openfile = reinterpret_cast<OpenFile*>(fi->fh);
  openfile->file->read(req, size, offset);
}

void Fs::fs_statfs(fuse_req_t req, fuse_ino_t ino) {
  DEBUG("fs_statfs");
  struct statvfs st = {
    .f_bsize = 4096,
    .f_frsize = 0,
    .f_blocks = 0,
    .f_bavail = 0,
    .f_files = 0,
    .f_ffree = 0,
    .f_favail = 0,
    .f_fsid = 0,
    .f_flag = ST_NOATIME | ST_NODEV | ST_NODIRATIME | ST_NOEXEC | ST_NOSUID | ST_RDONLY,
    .f_namemax = PATH_MAX,
  };
  fuse_reply_statfs(req, &st);
}
