EXE = freedoas
CC = cc
CFLAGS = -Wall -Wextra -pedantic -std=c99

build:
	$(CC) $(CFLAGS) -o $(EXE) freedoas.c
	chmod u+s $(EXE)

clean:
	rm -f $(EXE)
