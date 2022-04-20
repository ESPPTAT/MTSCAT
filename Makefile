export LD_LIBRARY_PATH=./
CXX = g++
CC= gcc
all:
	 #${CXX} -o test test_e_tickets.cpp e_tickets.cpp bn_pair.cpp   miracl.a -g
	 ${CXX} -o test test_e_tickets.cpp e_tickets.cpp bn_pair.cpp   miracl.a -O2
clean:
	rm -f test
