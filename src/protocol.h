#pragma once

#include <string_view>

#include <spdlog/fmt/fmt.h>

using FileId = uint16_t;
using UpdateId = uint32_t;

enum class ChecksumAlgorithm : uint8_t {
  Invalid,
  TimestampAndSize,
};

template <>
struct fmt::formatter<ChecksumAlgorithm> : formatter<std::string_view> {
  template <typename FormatContext>
  auto format(ChecksumAlgorithm c, FormatContext& ctx) const {
    std::string_view name = "<unknown>";
    switch (c) {
      case ChecksumAlgorithm::Invalid:
        name = "Invalid";

      case ChecksumAlgorithm::TimestampAndSize:
        name = "TimestampAndSize";
        break;
    }
    return formatter<std::string_view>::format(name, ctx);
  }
};

struct Checksum {
  ChecksumAlgorithm type;
  uint8_t padding[7];
  union {
    uint8_t bytes[32];
    struct {
      int64_t timestamp;
      uint64_t size;
      char padding[16];
    } timestamp_and_size;
  } value;

  bool operator==(const Checksum& rhs) const {
    return memcmp(&value.bytes, &rhs.value.bytes, sizeof(value.bytes)) == 0;
  }

 private:
  static std::string remove_trailing_zeroes(std::string str) {
    size_t i;
    size_t orig_size = str.size();
    for (i = 0; i < str.size() && str[orig_size - i - 1] == '0'; ++i)
      ;
    str.resize(orig_size - i);
    return str;
  }

 public:
  std::string str() const {
    std::string checksum_str = remove_trailing_zeroes(
      fmt::format("{:02x}{:02x}", static_cast<uint8_t>(type), fmt::join(value.bytes, "")));
    return checksum_str;
  }

  template <typename H>
  friend H AbslHashValue(H h, const Checksum& checksum) {
    return H::combine_contiguous(std::move(h), reinterpret_cast<const char*>(&checksum),
                                 sizeof(checksum));
  }
};
static_assert(sizeof(Checksum) == 40);

enum class UpdateType : uint8_t {
  // The server will send the full file.
  FullTransfer,

  // The client already reported that it has the desired version.
  Rebase,

  // Binary diff between old checksum and the new checksum.
  BinaryDiff,
};

enum class CompressionType : uint8_t {
  None,
};

enum class CommandType : uint8_t {
  // Client to server
  ClientHello = 0x00,
  ReportFileVersions = 0x01,
  CancelUpdate = 0x02,
  SetUpdatePriority = 0x03,

  // Server to client
  ServerHello = 0x80,
  ServerDie = 0x81,

  AddFile = 0x82,
  BeginFileUpdate = 0x83,
  FileUpdate = 0x84,
  EndFileUpdate = 0x85,
};

template <>
struct fmt::formatter<CommandType> : formatter<std::string_view> {
  template <typename FormatContext>
  auto format(CommandType c, FormatContext& ctx) const {
    std::string_view name = "<unknown>";
    switch (c) {
      case CommandType::ClientHello:
        name = "ClientHello";
        break;
      case CommandType::ReportFileVersions:
        name = "ReportFileVersions";
        break;
      case CommandType::CancelUpdate:
        name = "CancelUpdate";
        break;
      case CommandType::SetUpdatePriority:
        name = "SetUpdatePriority";
        break;
      case CommandType::ServerHello:
        name = "ServerHello";
        break;
      case CommandType::ServerDie:
        name = "ServerDie";
        break;
      case CommandType::AddFile:
        name = "AddFile";
        break;
      case CommandType::BeginFileUpdate:
        name = "BeginFileUpdate";
        break;
      case CommandType::FileUpdate:
        name = "FileUpdate";
        break;
      case CommandType::EndFileUpdate:
        name = "EndFileUpdate";
        break;
    }
    return formatter<std::string_view>::format(name, ctx);
  }
};

struct PacketHeader {
  uint32_t data_length;
  CommandType type;
  uint8_t padding[3];
};

// First, the client says hello, with a list of its available checksums.
struct ClientHello {
  static constexpr CommandType Type = CommandType::ClientHello;
  static size_t ExtraLength(ClientHello* p) {
    return sizeof(ChecksumAlgorithm) * p->checksum_count;
  }

  uint32_t version : 8;
  uint32_t padding : 23;
  uint32_t eager : 1;
  uint8_t checksum_count;
  ChecksumAlgorithm available_checksums[];
};

// The server responds with the selected checksum, or dies with an error message.
struct ServerHello {
  static constexpr CommandType Type = CommandType::ServerHello;
  static size_t ExtraLength(ServerHello* p) { return 0; }

  ChecksumAlgorithm selected_checksum;
};

struct ServerDie {
  static constexpr CommandType Type = CommandType::ServerDie;
  static size_t ExtraLength(ServerDie* p) { return p->message_length; }

  uint32_t message_length;
  char message[];
};

// The server announces its files to the client.
struct AddFile {
  static constexpr CommandType Type = CommandType::AddFile;
  static size_t ExtraLength(AddFile* p) { return p->filename_length; }

  FileId file_id;
  uint16_t filename_length;
  char filename[];
};

// The client responds to AddFile with its locally available versions.
struct ReportFileVersions {
  static constexpr CommandType Type = CommandType::ReportFileVersions;
  static size_t ExtraLength(ReportFileVersions* p) {
    return sizeof(ChecksumAlgorithm) * p->checksum_count;
  }

  FileId file_id;
  uint8_t padding;
  uint8_t checksum_count;
  Checksum checksums[];
};

// At any point after the client has reported its file versions, the server can begin an update.
struct BeginFileUpdate {
  static constexpr CommandType Type = CommandType::BeginFileUpdate;
  static size_t ExtraLength(BeginFileUpdate* p) { return 0; }

  UpdateId update_id;
  FileId file_id;
  UpdateType update_type;
  CompressionType compression_type;
  uint64_t size;
  int64_t mtime;
  Checksum old_checksum;
  Checksum new_checksum;
};

struct FileUpdate {
  static constexpr CommandType Type = CommandType::FileUpdate;
  static size_t ExtraLength(FileUpdate* p) { return p->data_length; }

  UpdateId update_id;
  uint32_t data_length;
  char data[];
};

struct EndFileUpdate {
  static constexpr CommandType Type = CommandType::EndFileUpdate;
  static size_t ExtraLength(EndFileUpdate* p) { return 0; }

  UpdateId update_id;
  uint8_t success : 1;
  uint8_t padding : 7;
};

struct CancelUpdate {
  static constexpr CommandType Type = CommandType::CancelUpdate;
  static size_t ExtraLength(CancelUpdate* p) { return 0; }

  UpdateId update_id;
};

// The client can request that a specified update be prioritized.
// The default priority is 128, with lower values being prioritized first.
using PriorityLevel = uint8_t;
inline constexpr PriorityLevel DEFAULT_PRIORITY_LEVEL = 128;

struct SetUpdatePriority {
  static constexpr CommandType Type = CommandType::SetUpdatePriority;
  static size_t ExtraLength(SetUpdatePriority* p) { return 0; }

  UpdateId update_id;
  PriorityLevel priority;
};
