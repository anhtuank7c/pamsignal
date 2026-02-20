# Step 1 - Initialize (Project Initialization)

- **Status**: Completed
- **Start Date**: 26/12/2025
- **Completion Date**: 26/12/2025
- **Update Date**: 20/02/2026

## 1. Objective

Establish the foundation for the **PAMSignal** project. Ensure the source code is scientifically organized, easily extensible, and has an automated build process with optimized performance.

## 2. Requirements

**Operating System**

Since the project focuses on Linux and requires the *libsystemd* library, to run this project you need to use a Linux operating system, such as Ubuntu or any other distribution.

**Dependencies**

```bash
sudo apt update
sudo apt install libsystemd-dev pkg-config build-essential meson ninja-build
```

After installation, you can clone the project and run the `meson` and `ninja` commands. The output will be the `pamsignal` executable file under `build/`.

```bash
git clone git@github.com:anhtuank7c/pamsignal.git
cd pamsignal
meson setup build
meson compile -C build
```

## 3. Directory Structure

```
pamsignal
    src/            Contains executable code (.c)
    include/        Contains header files (.h) for interface management.
    meson.build     Manages the build process.
    docs/           Manages documentation
```

## 4. Compilation Optimization with Meson

The C compiler has several options related to machine code optimization [see details here](https://gcc.gnu.org/onlinedocs/gcc-15.1.0/gcc/Optimize-Options.html)

By default in `meson.build`, I have specified `'buildtype=release'` as the default option. In Meson, a `release` build type automatically applies the `-O3` optimization level and strips debug symbols.

**Why Release mode?**

This is an optimization build type that helps the compiler rearrange machine instructions, eliminate redundant code, and increase log processing speed significantly compared to debug builds.

## 5. Results

- [x] Successfully initialized directory structure.

- [x] Meson configurations work well, correctly detects the `libsystemd` library.

- [x] Successfully compiled the first executable file (Sanity Check).

