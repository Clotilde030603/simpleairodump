CC = gcc
CFLAGS = -Wall -Wextra -O2
LDFLAGS = -lpcap

TARGET = airodump
SRCS = simple_airo.c
INSTALL_DIR = /usr/local/bin

all: $(INSTALL_DIR)/$(TARGET)

$(INSTALL_DIR)/$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRCS) $(LDFLAGS)
	@echo "Copying $(TARGET) to $(INSTALL_DIR)..."
	@sudo cp $(TARGET) $(INSTALL_DIR)
	@sudo chmod +x $(INSTALL_DIR)/$(TARGET)
	@echo "Installation complete. You can now run 'sudo $(TARGET) mon0'"

clean:
	rm -f $(TARGET)
	@echo "Cleaned up build files."
