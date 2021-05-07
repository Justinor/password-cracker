CC := clang
CFLAGS := -g -Wall -Werror

# Special flags to find libssl-dev includes
CFLAGS += -I/home/justin/.local/include
LDFLAGS := -L/home/justin/.local/lib

all: password-cracker

clean:
	rm -rf password-cracker password-cracker.dSYM

password-cracker: password-cracker.c
	$(CC) $(CFLAGS) -o password-cracker password-cracker.c $(LDFLAGS) -lcrypto -lpthread -lm