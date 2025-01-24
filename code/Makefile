SRC_FILES=main.cpp api.cpp request.cpp server.cpp utils.cpp
OUT_EXEC=a.out

LIBS= -lssl -lcrypto

SANITIZE=-fsanitize=address -fsanitize=null -g3
CXXFLAGS=-Wall -Wextra $(SANITIZE)

OBJ_DIR=./objects
OBJ_FILES=$(SRC_FILES:%.cpp=$(OBJ_DIR)/%.o)

all: $(OUT_EXEC)

$(OUT_EXEC): $(OBJ_FILES)
	@echo "Linking..."
	@c++ $(CXXFLAGS) $^ $(LIBS) -o $(OUT_EXEC)

$(OBJ_DIR)/%.o: %.cpp | $(OBJ_DIR)
	@echo "Compiling: $<"
	@c++ $(CXXFLAGS) -c $< $(INCLUDES) -o $@

$(OBJ_DIR):
	@mkdir -p $(OBJ_DIR)

clean:
	@echo "Cleaning up..."
	@rm -rf $(OUT_EXEC) $(OBJ_DIR)

run: $(OUT_EXEC)
	@echo "Running the program..."
	@./$(OUT_EXEC)

install:
	@echo "Checking dependencies..."
	sudo apt install libssl-dev nlohmann-json3-dev
	@echo "All dependencies are installed!"

re: clean all

.PHONY: all clean run install re
