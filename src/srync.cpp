#include "srync.h"

#include <err.h>
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
  printf("Usage: srync [OPTION]... [-H HOST] MOUNTPOINT\n");
  printf("       srync [OPTION]... -l PATH...\n");
  printf("\n");
  printf("  -h           print help\n");
  printf("  -V           print version\n");
  printf("  -v           increase verbosity (can be repeated)\n");
  printf("\n");
  printf("  -l           listen for incoming connections\n");
  printf("  -p PORT      use PORT instead of default (5038)\n");
  printf("  -H HOST      use HOST instead of default (localhost)\n");
  exit(rc);
}

int main(int argc, char** argv) {
  int opt;
  int verbosity = 0;
  bool listen = false;
  std::string host = "localhost";
  int port = 5038;

  while ((opt = getopt(argc, argv, "hVvlH:p:")) != -1) {
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
        fprintf(stderr, "srync: unrecognized option '%s'\n", optarg);
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
