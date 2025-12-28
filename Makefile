# ===== Project settings =====
BUILD_DIR := build
BIN_DIR   := bin
TARGET    := pamsignal

# Default build type
BUILD_TYPE ?= Release

# ===== Targets =====
all: configure build

configure:
	mkdir -p $(BUILD_DIR)
	cmake -S . -B $(BUILD_DIR) \
		-DCMAKE_BUILD_TYPE=$(BUILD_TYPE)

build:
	cmake --build $(BUILD_DIR)

clean:
	rm -rf $(BUILD_DIR) $(BIN_DIR)

run: all
	./$(BIN_DIR)/$(TARGET)

.PHONY: all configure build clean run
