project(
  'srync',
  'cpp',
  default_options: [
    'cpp_std=c++17',
    'cpp_rtti=false',
  ]
)

if meson.get_compiler('cpp').get_id() == 'clang'
  add_project_arguments(
    '-Wthread-safety',
    language: 'cpp'
  )
endif

add_project_link_arguments(['-lstdc++fs'], language : 'cpp')

absl = subproject('abseil-cpp')
absl_container = absl.get_variable('absl_container_dep')
absl_hash = absl.get_variable('absl_hash_dep')
absl_strings = absl.get_variable('absl_strings_dep')
absl_synchronization = absl.get_variable('absl_synchronization_dep')

spdlog_proj = subproject('spdlog', default_options: ['compile_library=true', 'tests=false'])
spdlog = spdlog_proj.get_variable('spdlog_dep')

libfuse_proj = subproject('libfuse')
libfuse = libfuse_proj.get_variable('libfuse_dep')

srync = executable(
  'srync',
  sources: [
    'src/srync.cpp'
  ],
  include_directories: ['src'],
  dependencies: [
    absl_container,
    absl_hash,
    absl_strings,
    absl_synchronization,
    libfuse,
    spdlog,
  ],
)
