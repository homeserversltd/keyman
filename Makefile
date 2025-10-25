CC = gcc
CFLAGS = -Wall -Wextra -O2 -std=c99
LDFLAGS = -lssl -lcrypto

TARGET = keyman-crypto
SOURCE = keyman-crypto.c

.PHONY: all clean install

all: $(TARGET)

$(TARGET): $(SOURCE)
	$(CC) $(CFLAGS) -o $(TARGET) $(SOURCE) $(LDFLAGS)

clean:
	rm -f $(TARGET)

install: $(TARGET)
	cp $(TARGET) /vault/keyman/
	chmod 755 /vault/keyman/$(TARGET)
	chown root:root /vault/keyman/$(TARGET)

.DEFAULT_GOAL := all
