PROJECT_NAME = ctrtool

CC = gcc
CFLAGS =
LDFLAGS = -lcrypto

SRC_DIR = .
BUILD_DIR = build
BIN_DIR = bin

SRCS = $(shell find $(SRC_DIR) -name '*.c')
OBJS = $(SRCS:$(SRC_DIR)/%.c=$(BUILD_DIR)/%.o)

ifeq ($(OS),Windows_NT)
	TARGET_EXT = .exe
else 
	TARGET_EXT = 
endif
TARGET = $(BIN_DIR)/$(PROJECT_NAME)$(TARGET_EXT)

all: $(TARGET)

$(TARGET): $(OBJS)
	@mkdir -p $(dir $@)
	$(CC) $(OBJS) -o $@ $(LDFLAGS)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(BUILD_DIR)
	rm -f $(TARGET)

.PHONY: all clean