project('pamsignal', 'c',
  version: '0.1',
  default_options: [
    'c_std=gnu17',
    'warning_level=2',
    'buildtype=release',
  ]
)

add_project_arguments('-Wshadow', language: 'c')

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
