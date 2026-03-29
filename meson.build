project('pamsignal', 'c',
  version: '0.0.1',
  default_options: [
    'c_std=gnu17',
    'warning_level=2',
    'buildtype=release',
    'b_pie=true',
  ]
)

add_project_arguments(
  '-Wshadow',
  '-Wformat-security',
  '-fstack-protector-strong',
  '-D_FORTIFY_SOURCE=2',
  language: 'c'
)

add_project_link_arguments(
  '-Wl,-z,relro',
  '-Wl,-z,now',
  language: 'c'
)

libsystemd_dep = dependency('libsystemd')

inc = include_directories('include')

srcs = [
  'src/init.c',
  'src/journal_watch.c',
  'src/main.c',
  'src/utils.c'
]

executable('pamsignal',
  srcs,
  include_directories: inc,
  dependencies: libsystemd_dep,
  install: false
)
