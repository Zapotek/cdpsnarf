# $Id: Makefile 778 2008-02-10 15:12:35Z zapotek $

all:
	gcc -O3 -Wall -lm -lpcap cdpsnarf.c -o bin/cdpsnarf
	