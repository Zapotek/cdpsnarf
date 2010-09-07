
all:
	gcc -O3 -Wall -lm -lpcap cdpsnarf.c -o cdpsnarf
	