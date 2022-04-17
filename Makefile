CC=g++
CFLAGS=-std=c++17 -Wall -Wextra -pedantic

ipk-sniffer: src/*.cpp src/*.h main.cpp
	$(CC) $(CFLAGS) main.cpp src/*.cpp -o ipk-sniffer -lpcap
