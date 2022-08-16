#pragma once

#include <unistd.h>

#include <filesystem>
#include <string_view>
#include <vector>

#include <absl/hash/hash.h>

#define SRYNC_VERSION "0.1.0"
#define SRYNC_PROTOCOL_VERSION 2

#define TRACE(...)                                       \
  do {                                                   \
    if (spdlog::get_level() <= (spdlog::level::trace)) { \
      (spdlog::trace)(__VA_ARGS__);                      \
    }                                                    \
  } while (0)

#define DEBUG(...)                                       \
  do {                                                   \
    if (spdlog::get_level() <= (spdlog::level::debug)) { \
      (spdlog::debug)(__VA_ARGS__);                      \
    }                                                    \
  } while (0)

#define INFO(...)                                       \
  do {                                                  \
    if (spdlog::get_level() <= (spdlog::level::info)) { \
      (spdlog::info)(__VA_ARGS__);                      \
    }                                                   \
  } while (0)

#define WARN(...)                                       \
  do {                                                  \
    if (spdlog::get_level() <= (spdlog::level::warn)) { \
      (spdlog::warn)(__VA_ARGS__);                      \
    }                                                   \
  } while (0)

#define ERROR(...)                                     \
  do {                                                 \
    if (spdlog::get_level() <= (spdlog::level::err)) { \
      (spdlog::error)(__VA_ARGS__);                    \
    }                                                  \
  } while (0)

#define CRITICAL(...)                                       \
  do {                                                      \
    if (spdlog::get_level() <= (spdlog::level::critical)) { \
      (spdlog::critical)(__VA_ARGS__);                      \
    }                                                       \
  } while (0)

#define CHECK(cond)                                \
  do {                                             \
    if (!(cond)) {                                 \
      spdlog::critical("Check failed: %s", #cond); \
      abort();                                     \
    }                                              \
  } while (0)

#define CHECK_GT(lhs, rhs) CHECK((lhs) > (rhs))
#define CHECK_GE(lhs, rhs) CHECK((lhs) >= (rhs))
#define CHECK_EQ(lhs, rhs) CHECK((lhs) == (rhs))
#define CHECK_LE(lhs, rhs) CHECK((lhs) <= (rhs))
#define CHECK_LT(lhs, rhs) CHECK((lhs) < (rhs))

#define CHECK_NE(lhs, rhs) CHECK((lhs) != (rhs))

struct unique_fd {
  unique_fd() = default;
  explicit unique_fd(int fd) : fd_(fd) {}
  ~unique_fd() {
    if (fd_ != -1) {
      close(fd_);
    }
  }

  unique_fd(const unique_fd& copy) = delete;
  unique_fd(unique_fd&& move) {
    this->fd_ = move.fd_;
    move.fd_ = -1;
  }

  unique_fd& operator=(const unique_fd& copy) = delete;
  unique_fd& operator=(unique_fd&& move) {
    if (this != &move) {
      this->fd_ = move.fd_;
      move.fd_ = -1;
    }
    return *this;
  }

  bool operator==(int fd) const { return fd == fd_; }
  bool operator!=(int fd) const { return fd != fd_; }

  int get() const { return fd_; }

  void reset(int new_fd = -1) {
    if (fd_ != -1) {
      close(fd_);
    }
    fd_ = new_fd;
  }

 private:
  int fd_ = -1;
};

struct borrowed_fd {
  /* implicit */ borrowed_fd(int fd) : fd_(fd) {}
  /* implicit */ borrowed_fd(const unique_fd& fd) : fd_(fd.get()) {}
  borrowed_fd(const borrowed_fd& copy) : fd_(copy.get()) {}

  borrowed_fd& operator=(const borrowed_fd& copy) {
    this->fd_ = copy.get();
    return *this;
  }

  borrowed_fd& operator=(int fd) {
    this->fd_ = fd;
    return *this;
  }

  borrowed_fd& operator=(const unique_fd& fd) {
    this->fd_ = fd.get();
    return *this;
  }

  bool operator==(int fd) const { return fd == get(); }
  bool operator!=(int fd) const { return fd != get(); }
  bool operator==(const borrowed_fd& fd) const { return fd.get() == get(); }
  bool operator!=(const borrowed_fd& fd) const { return fd.get() != get(); }

  int get() const { return fd_; }

  template <typename H>
  friend H AbslHashValue(H h, const borrowed_fd& fd) {
    return H::combine(std::move(h), fd.get());
  }

 private:
  int fd_;
};

int client_main(std::string host, int port, std::filesystem::path mountpoint);
int server_main(std::string host, int port, std::vector<std::filesystem::path> local_paths);
