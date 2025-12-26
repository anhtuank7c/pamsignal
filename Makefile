CC = gcc
CFLAGS = -Wall -Wextra -Iinclude -O2
LDFLAGS = -lsystemd

# Source files
SRCS = $(wildcard src/*.c)
OBJS = $(SRCS:.c=.o)
TARGET = pamsignal

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: all clean
