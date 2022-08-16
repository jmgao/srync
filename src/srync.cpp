#include "srync.h"

#include <err.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <filesystem>
#include <string_view>
#include <vector>

#include <spdlog/spdlog.h>

#include "fs.h"
#include "srync.h"

[[noreturn]] static void usage(int rc) {
  printf("Usage: srync [OPTION]... -l PATH...\n");
  printf("       Listen for incoming connections, exposing PATHs as files.\n");
  printf("\n");
  printf("       srync [OPTION]... MOUNTPOINT\n");
  printf("       Connect to a srync daemon and mount it at MOUNTPOINT");
  printf("\n");
  printf("\n");
  printf("  -l, --listen         listen for incoming connections\n");
  printf("  -H, --host HOST      use HOST instead of default (localhost)\n");
  printf("  -p, --port PORT      use PORT instead of default (5038)\n");
  printf("  -v, --verbose        increase verbosity (can be repeated)\n");
  printf("\n");
  printf("  -h, --help           print help\n");
  printf("  -V, --version        print version\n");
  exit(rc);
}

int main(int argc, char** argv) {
  int opt;
  int verbosity = 0;
  bool listen = false;
  std::string host = "localhost";
  int port = 5038;

  struct option longopts[] = {
    {
      .name = "help",
      .has_arg = false,
      .flag = nullptr,
      .val = 'h',
    },
    {
      .name = "version",
      .has_arg = false,
      .flag = nullptr,
      .val = 'V',
    },
    {
      .name = "verbose",
      .has_arg = false,
      .flag = nullptr,
      .val = 'v',
    },
    {
      .name = "listen",
      .has_arg = false,
      .flag = nullptr,
      .val = 'l',
    },
    {
      .name = "port",
      .has_arg = true,
      .flag = nullptr,
      .val = 'p',
    },
    {
      .name = "host",
      .has_arg = true,
      .flag = nullptr,
      .val = 'H',
    },
    {
      .name = nullptr,
      .has_arg = false,
      .flag = nullptr,
      .val = 0,
    },
  };

  while ((opt = getopt_long(argc, argv, "hVvlH:p:", longopts, nullptr)) != -1) {
    switch (opt) {
      case 'h':
        usage(0);

      case 'V':
        printf("srync %s\n", SRYNC_VERSION);
        exit(0);

      case 'v':
        ++verbosity;
        break;

      case 'l':
        listen = true;
        break;

      case 'H':
        host = optarg;
        break;

      case 'p':
        port = atoi(optarg);
        if (port <= 0 || port > 65535) {
          fprintf(stderr, "srync: invalid port -- '%s'\n", optarg);
          exit(1);
        }
        break;

      case '?':
        exit(1);
    }
  }

  switch (verbosity) {
    case 0:
      spdlog::set_level(spdlog::level::info);
      break;
    case 1:
      spdlog::set_level(spdlog::level::debug);
      break;
    case 2:
      spdlog::set_level(spdlog::level::trace);
      break;
  }

  argc -= optind;
  argv += optind;

  if (listen) {
    if (argc == 0) {
      fprintf(stderr, "srync: no paths specified for server\n");
      usage(1);
    }

    std::vector<std::filesystem::path> local_paths;
    for (int i = 0; i < argc; ++i) {
      local_paths.push_back(argv[i]);
    }

    return server_main(std::move(host), port, local_paths);
  } else {
    if (argc != 1) {
      usage(1);
    }

    std::filesystem::path mountpoint = argv[0];
    return client_main(std::move(host), port, mountpoint);
  }
}
