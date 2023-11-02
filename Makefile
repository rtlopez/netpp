CXXFLAGS=-Wall -std=c++17 -Og
LDFLAGS=
DEPS=$(wildcard src/*.h) Makefile
SRCS=$(wildcard src/*.cpp)
OBJS=$(SRCS:.cpp=.o)
TARGET_S=server
TARGET_C=client

.PHONY: all clean dump

%.o: %.cpp $(DEPS)
	$(CXX) -c -o $@ $< $(CXXFLAGS)

$(TARGET_S): src/server.o
	$(CXX) -o $@ $^ $(CXXFLAGS) $(LDFLAGS)

$(TARGET_C): src/client.o
	$(CXX) -o $@ $^ $(CXXFLAGS) $(LDFLAGS)

all: $(TARGET_S) $(TARGET_C)

clean:
	$(RM) $(TARGET_S) $(TARGET_C) $(OBJS)

dump:
	@echo "Target: " $(TARGET_S) $(TARGET_C)
	@echo "SRCS: " $(SRCS)
	@echo "OBJS: " $(OBJS)
	@echo "DEPS: " $(DEPS)

