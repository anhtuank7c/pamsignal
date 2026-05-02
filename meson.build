project('pamsignal', 'c',
  version: '0.2.3',
  default_options: [
    'c_std=gnu17',
    'warning_level=2',
    'buildtype=release',
    'b_pie=true',
  ]
)

cc = meson.get_compiler('c')

# Always-on flags: portable across gcc/clang and broadly supported on the
# project's target distros (Debian/Ubuntu/Fedora/RHEL).
add_project_arguments(
  '-Wshadow',
  '-Wformat=2',
  '-Werror=format-security',
  '-fstack-protector-strong',
  '-D_GNU_SOURCE',
  language: 'c'
)

# _FORTIFY_SOURCE=3 strengthens runtime overflow checks (glibc >=2.34, gcc >=12).
# Undefine first so we don't conflict with dpkg-buildflags / rpm hardening flags
# that pre-define =2.
fortify_args = cc.get_supported_arguments(
  '-U_FORTIFY_SOURCE',
  '-D_FORTIFY_SOURCE=3',
)
if fortify_args.length() == 2
  add_project_arguments(fortify_args, language: 'c')
else
  add_project_arguments('-D_FORTIFY_SOURCE=2', language: 'c')
endif

# Best-effort hardening flags: enabled only if the toolchain supports them.
add_project_arguments(
  cc.get_supported_arguments(
    '-fstack-clash-protection',  # block large-frame stack-clash attacks
    '-fcf-protection=full',      # Intel CET (IBT + shadow stack)
    '-Wnull-dereference',
    '-Wstrict-overflow=3',
  ),
  language: 'c',
)

# Linker hardening
add_project_link_arguments(
  '-Wl,-z,relro',
  '-Wl,-z,now',
  '-Wl,-z,noexecstack',
  language: 'c'
)
add_project_link_arguments(
  cc.get_supported_link_arguments(
    '-Wl,-z,separate-code',  # disjoint RX / RW segments
  ),
  language: 'c',
)

libsystemd_dep = dependency('libsystemd')

inc = include_directories('include')

srcs = [
  'src/config.c',
  'src/init.c',
  'src/journal_watch.c',
  'src/main.c',
  'src/notify.c',
  'src/utils.c'
]

executable('pamsignal',
  srcs,
  include_directories: inc,
  dependencies: libsystemd_dep,
  install: true
)

install_data('pamsignal.service',
  install_dir: '/etc/systemd/system'
)

install_data('pamsignal.conf.example',
  install_dir: get_option('sysconfdir') / 'pamsignal',
  rename: 'pamsignal.conf'
)

# --- Tests ---
cmocka_dep = dependency('cmocka', required: false)

if cmocka_dep.found()
  test('test_utils',
    executable('test_utils',
      'tests/test_utils.c',
      'src/utils.c',
      include_directories: inc,
      dependencies: [cmocka_dep, libsystemd_dep],
    ),
    protocol: 'exitcode',
  )

  test('test_config',
    executable('test_config',
      'tests/test_config.c',
      'src/config.c',
      include_directories: inc,
      dependencies: [cmocka_dep, libsystemd_dep],
    ),
    protocol: 'exitcode',
  )

  test('test_notify',
    executable('test_notify',
      'tests/test_notify.c',
      'src/notify.c',
      'src/utils.c',
      'src/config.c',
      include_directories: inc,
      dependencies: [cmocka_dep, libsystemd_dep],
    ),
    protocol: 'exitcode',
  )

  # test_journal_watch #includes ../src/journal_watch.c so it can drive the
  # file-static fail_table state and ps_track_failed_login. Do NOT also list
  # src/journal_watch.c here — that would produce duplicate symbols.
  test('test_journal_watch',
    executable('test_journal_watch',
      'tests/test_journal_watch.c',
      'src/notify.c',
      'src/utils.c',
      'src/config.c',
      include_directories: inc,
      dependencies: [cmocka_dep, libsystemd_dep],
    ),
    protocol: 'exitcode',
  )
endif

# --- Fuzzing ---
#
# Opt-in libFuzzer harness for ps_parse_message. Requires clang because
# -fsanitize=fuzzer is a clang-only feature. Configure with:
#   CC=clang-21 meson setup -Dfuzz=enabled build-fuzz
#   meson compile -C build-fuzz fuzz_parse_message
#   ./build-fuzz/fuzz_parse_message tests/fuzz/parse_message_corpus -max_total_time=60
#
# The harness binary is intentionally NOT registered with `test()` — fuzzing
# runs for as long as you let it; CI should call it with -max_total_time.

fuzz_opt = get_option('fuzz')
if fuzz_opt.allowed()
  if cc.get_id() == 'clang'
    fuzz_args = [
      '-fsanitize=fuzzer,address,undefined',
      '-fno-sanitize-recover=undefined',
      '-O1',
      '-g',
    ]
    executable('fuzz_parse_message',
      'tests/fuzz_parse_message.c',
      'src/utils.c',
      include_directories: inc,
      c_args: fuzz_args,
      link_args: fuzz_args,
      build_by_default: false,
    )
  elif fuzz_opt.enabled()
    error(
      '-Dfuzz=enabled requires clang (got @0@). Reconfigure with CC=clang.'
      .format(cc.get_id())
    )
  endif
endif
