CELLAR=$(HOME)/.brew/Cellar
OPENSSL=$(CELLAR)/openssl@3/3.4.0
NLOHMANN=$(CELLAR)/nlohmann-json/3.11.3

SRC_FILES=main.cpp api.cpp request.cpp server.cpp utils.cpp
OUT_EXEC=a.out

INCLUDES=-I$(OPENSSL)/include  -I$(NLOHMANN)/include

LIBS=-L$(OPENSSL)/lib -lssl -lcrypto

SANITIZE=-fsanitize=address -fsanitize=null -g3
CXXFLAGS=-Wall -Wextra $(SANITIZE)

OBJ_DIR=./objects
OBJ_FILES=$(SRC_FILES:%.cpp=$(OBJ_DIR)/%.o)

all: check_deps $(OUT_EXEC)

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

check_deps:
	@echo "Checking dependencies..."

	# Check if OpenSSL exists
	@if [ ! -d "$(OPENSSL)" ]; then \
		echo "Error: OpenSSL is not installed at $(OPENSSL)"; \
		exit 1; \
	fi
	
	
	# Check if Nlohmann JSON exists
	@if [ ! -d "$(NLOHMANN)" ]; then \
		echo "Error: Nlohmann JSON is not installed at $(NLOHMANN)"; \
		exit 1; \
	fi

	@echo "All dependencies are installed!"

.PHONY: all clean run check_deps
