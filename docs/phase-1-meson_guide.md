# Meson & Ninja: Build Tools

- **Status**: Completed
- **Start Date**: 20/02/2026
- **Completion Date**: 20/02/2026

Meson and Ninja work together to replace CMake and Make. They are designed to be extremely fast and user-friendly.

* **Meson** corresponds to **CMake**: It reads a configuration file (`meson.build`) and generates build files.
* **Ninja** corresponds to **Make**: It reads the generated build files and actually compiles the code.

## File Equivalents

| CMake System           | Meson System          | Purpose                                        |
|------------------------|-----------------------|------------------------------------------------|
| `CMakeLists.txt`       | `meson.build`         | Defines the project, targets, and dependencies |
| `cmake -S . -B build`  | `meson setup build`   | Generate the build files within a directory    |
| `make`                 | `ninja`               | Actually compile the code                      |
| `build/Makefile`       | `build/build.ninja`   | The generated files used to compile            |

## How to use Meson & Ninja

Here is the standard workflow you will use every day.

### 1. Configure the project (Do this once)
This tells Meson to read `meson.build` and create a build directory.

```bash
# General format: meson setup <build-directory>
meson setup build
```

*Note: You can pass options here, like `--buildtype=release` or `--buildtype=debug`.*

### 2. Build the project (Do this whenever you change code)
Ask Meson to compile the changes. It will automatically call Ninja under the hood.

```bash
# General format: meson compile -C <build-directory>
meson compile -C build 
```

*(Alternatively, you can just cd into the build directory and type `ninja`)*

### 3. Clean the project
With Meson, you generally don't need a `clean` command. Because it's so fast, you can simply delete the build directory and configure it again if things get very messy.

```bash
rm -rf build && meson setup build
```

## Why use Meson over CMake?

1. **Syntax**: `meson.build` uses a clean, Python-like syntax that is much easier to read and write than `CMakeLists.txt`.
2. **Speed**: It is incredibly fast at generating build files.
3. **Ninja by default**: Make is notoriously slow for large projects. Ninja is designed to be as fast as possible, and Meson uses it by default.
4. **Dependency Management**: Finding and using external libraries (like `systemd` via `pkg-config`) is generally simpler and less wordy in Meson.

## Why use Meson over raw GCC commands?

If you were to compile this project manually using `gcc`, the command would look something like this:

```bash
gcc src/init.c src/journal_watch.c src/main.c src/utils.c \
    -Iinclude -o build/pamsignal \
    $(pkg-config --cflags --libs libsystemd) \
    -Wall -Wextra -Wshadow -std=gnu17 -O2
```

As the project grows, managing this single command becomes extremely difficult:

1. **Incremental Builds**: The raw `gcc` command recompiles **every** source file every time you run it, even if you only changed one line in one file. Meson (via Ninja) is smart enough to detect exactly which files changed and only recompiles those, making your workflow significantly faster.
2. **Complexity Management**: Adding new directories, features, or standardizing compiler flags across multiple developers creates a massive, prone-to-error `gcc` command. `meson.build` organizes this logically line-by-line.
3. **Build Configurations**: Meson effortlessly switches between profiles (like Debug for development vs. Release for production builds) just by passing a flag (`meson setup build --buildtype=debug`). With raw GCC, you would have to manually swap out `-O2` for `-g -O0` and trace dependencies manually every time.
