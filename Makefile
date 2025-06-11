EXE = freedoas
CC = cc
CFLAGS = -g -Wall -Wextra -pedantic -std=c99

build:
	$(CC) $(CFLAGS) -o $(EXE) freedoas.c
	chmod +s $(EXE)

clean:
	rm -f $(EXE)
