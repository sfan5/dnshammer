CXXFLAGS = -pipe -std=c++11 -Wall -Iinclude
LDFLAGS = -pthread

CXXFLAGS += -O2 -g

PREFIX ?= /usr
BINDIR ?= $(PREFIX)/bin

SRC = socket.cpp dns.cpp query.cpp main.cpp
OBJ = $(addsuffix .o, $(basename $(SRC)))

all: dnshammer

dnshammer: $(OBJ)
	$(CXX) $(CXXFLAGS) -o $@ $(OBJ) $(LDFLAGS)

%.o: %.cpp include/*
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ)

install:
	install -pDm755 dnsh $(DESTDIR)$(BINDIR)/dnsh

.PHONY: all clean
