CC = x86_64-w64-mingw32-gcc 
SRC_DIR = src
SRCS = $(wildcard $(SRC_DIR)/*.c)
EXECUTABLE = readpe.exe

all: $(EXECUTABLE)
$(EXECUTABLE): 
	$(CC) -o $@ $(SRCS)


