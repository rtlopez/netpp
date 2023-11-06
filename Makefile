CXXFLAGS=-Wall -std=c++17 -O0 -g3 -Iinclude/
LDFLAGS=
DEPS=$(shell find include/ -name *.h) Makefile
SRCS=$(wildcard src/*.cpp)
OBJS=$(SRCS:.cpp=.o)
TARGET_S=server
TARGET_C=client

.PHONY: all clean dump

%.o: %.cpp $(DEPS)
	$(CXX) -c -o $@ $< $(CXXFLAGS)

all: $(TARGET_S) $(TARGET_C)

$(TARGET_S): src/server.o
	$(CXX) -o $@ $^ $(CXXFLAGS) $(LDFLAGS)

$(TARGET_C): src/client.o
	$(CXX) -o $@ $^ $(CXXFLAGS) $(LDFLAGS)

clean:
	$(RM) $(TARGET_S) $(TARGET_C) $(OBJS)

dump:
	@echo "Target: " $(TARGET_S) $(TARGET_C)
	@echo "SRCS: " $(SRCS)
	@echo "OBJS: " $(OBJS)
	@echo "DEPS: " $(DEPS)

