# Step 1 - Initialize (Project Initialization)

- **Status**: Completed
- **Start Date**: 26/12/2025
- **Completion Date**: 26/12/2025

## 1. Objective

Establish the foundation for the **PAMSignal** project. Ensure the source code is scientifically organized, easily extensible, and has an automated build process with optimized performance.

## 2. Requirements

**Operating System**

Since the project focuses on Linux and requires the *libsystemd* library, to run this project you need to use a Linux operating system, such as Ubuntu or any other distribution.

**Dependencies**

```bash
sudo apt update
sudo apt install libsystemd-dev pkg-config build-essential cmake
```

After installation, you can clone the project and run the `make` command. The output will be the `pamsignal` executable file.

```bash
git clone git@github.com:anhtuank7c/pamsignal.git
cd pamsignal
make
```

## 3. Directory Structure

```
pamsignal
    src/            Contains executable code (.c)
    include/        Contains header files (.h) for interface management.
    Makefile        Manages the build process.
    docs/           Manages documentation
```

## 4. Compilation Optimization with Makefile

The C compiler has several options related to machine code optimization [see details here](https://gcc.gnu.org/onlinedocs/gcc-15.1.0/gcc/Optimize-Options.html)

I use the `-O2` optimization flag during compilation.

**Why -O2?**

This is an optimization level that helps the compiler rearrange machine instructions, eliminate redundant code, and increase log processing speed without inflating file size like `-O3`.

## 5. Results

- [x] Successfully initialized directory structure.

- [x] Makefile works well, correctly detects the `libsystemd` library.

- [x] Successfully compiled the first executable file (Sanity Check).

