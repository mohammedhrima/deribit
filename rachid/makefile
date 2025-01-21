CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -Werror -lpthread -lcurl

TARGET = app

LDLIBS = -lcurl -lpthread

SRCS = srcs/main.cpp srcs/APIClient.cpp srcs/WebSocketServer.cpp
OBJS = $(SRCS:.cpp=.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(OBJS) $(LDLIBS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)

rebuild: clean all
