#pragma once

#include <sys/epoll.h>
#include <sys/uio.h>

#include "iovector.h"
#include "protocol.h"
#include "srync.h"

struct Connection {
  Connection(borrowed_fd epollfd, unique_fd fd) : epfd_(epollfd), fd_(std::move(fd)) {
    struct epoll_event event;
    event.events = EPOLLIN;
    event.data.fd = fd_.get();
    if (epoll_ctl(epfd_.get(), EPOLL_CTL_ADD, fd_.get(), &event) != 0) {
      ERROR("epoll_ctl failed to modify client: {}", strerror(errno));
      exit(1);
    }
  }

  virtual ~Connection() {
    if (fd_ != -1) {
      struct epoll_event event;
      event.events = EPOLLIN;
      event.data.fd = fd_.get();
      if (epoll_ctl(epfd_.get(), EPOLL_CTL_DEL, fd_.get(), &event) != 0) {
        ERROR("epoll_ctl failed to remove client: {}", strerror(errno));
        exit(1);
      }
    }
  }

  Connection(const Connection& copy) = delete;
  Connection(Connection&& move) = default;

  Connection& operator=(const Connection& copy) = delete;
  Connection& operator=(Connection&& move) = default;

  void write(CommandType command, Block packet_data) {
    if (packet_data.size() > UINT32_MAX) {
      ERROR("packet size overflow");
      exit(1);
    }

    Block header_buf(sizeof(PacketHeader));
    PacketHeader header = {
      .data_length = static_cast<uint32_t>(packet_data.size()),
      .type = command,
      .padding = {},
    };
    memcpy(header_buf.data(), &header, sizeof(header));

    output_queue_.append(std::move(header_buf));
    output_queue_.append(std::move(packet_data));
    update_epollout();
  }

  bool process_events(int mask) {
    if (mask & EPOLLIN) {
      if (!do_read()) {
        return false;
      }
    }
    if (mask & EPOLLOUT) {
      if (!flush_writes()) {
        return false;
      }
    }
    return true;
  }

  borrowed_fd pollfd() { return fd_; }

 protected:
  virtual bool process_read(const PacketHeader& header, Block data) = 0;

  size_t bytes_queued() const { return output_queue_.size(); }

  bool flush_writes() {
    while (!output_queue_.empty()) {
      std::vector<struct iovec> iovecs = output_queue_.iovecs();
      ssize_t rc = TEMP_FAILURE_RETRY(writev(fd_.get(), iovecs.data(), iovecs.size()));
      if (rc == -1) {
        if (errno == EAGAIN) {
          break;
        }
        ERROR("writev failed (fd={}): {}", fd_.get(), strerror(errno));
        return false;
      } else if (rc == 0) {
        WARN("Connection closed (fd={})", fd_.get());
        return false;
      }
      output_queue_.drop_front(rc);
    }

    // Set the state of EPOLLOUT appropriately.
    update_epollout();
    return true;
  }

  template <typename T>
  T* packet_cast(Block& block) {
    if (block.size() < sizeof(T)) {
      ERROR("Packet not big enough to hold packet header for {}", T::Type);
      return nullptr;
    }
    T* packet = reinterpret_cast<T*>(block.data());
    size_t expected_size = sizeof(T) + T::ExtraLength(packet);
    if (block.size() != expected_size) {
      ERROR("Unexpected size for {}: expected {} bytes but got {}", T::Type, expected_size,
            block.size());
      return nullptr;
    }
    return packet;
  }

 private:
  bool do_read() {
    while (true) {
      Block block(4096);
      ssize_t rc = TEMP_FAILURE_RETRY(read(fd_.get(), block.data(), block.size()));
      if (rc == -1) {
        if (errno == EAGAIN) {
          break;
        }
        ERROR("read failed (fd={}): {}", fd_.get(), strerror(errno));
        return false;
      } else if (rc == 0) {
        return false;
      }
      block.resize(rc);
      input_queue_.append(std::move(block));
    }

    while (true) {
      // Piece together the ruins of a packet.
      if (!packet_header_) {
        if (input_queue_.size() < sizeof(PacketHeader)) {
          return true;
        }
        PacketHeader header;
        input_queue_.take_front(sizeof(header)).coalesced([&header](const char* p, size_t size) {
          memcpy(&header, p, size);
        });
        packet_header_ = header;
      }

      if (input_queue_.size() < packet_header_->data_length) {
        return true;
      }

      Block packet_data = input_queue_.take_front(packet_header_->data_length).coalesce();
      if (!process_read(*packet_header_, std::move(packet_data))) {
        return false;
      }
      packet_header_.reset();
    }
    return true;
  }

  void update_epollout() {
    if (!output_queue_.empty() != epollout_) {
      struct epoll_event event;
      event.events = EPOLLIN;

      epollout_ = !output_queue_.empty();
      if (epollout_) {
        TRACE("Registering EPOLLOUT on fd {}", fd_.get());
        event.events |= EPOLLOUT;
      } else {
        TRACE("Unregistering EPOLLOUT on fd {}", fd_.get());
      }

      event.data.fd = fd_.get();
      if (epoll_ctl(epfd_.get(), EPOLL_CTL_MOD, fd_.get(), &event) != 0) {
        ERROR("epoll_ctl failed: {}", strerror(errno));
        exit(1);
      }
    }
  }

 protected:
  std::optional<PacketHeader> packet_header_;

  IOVector input_queue_;

  bool epollout_ = false;
  IOVector output_queue_;

  borrowed_fd epfd_;
  unique_fd fd_;
};
