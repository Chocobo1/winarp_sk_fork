# compiler options
CXX			 = g++
CXXFLAGS	 = -D__GNU_LIBRARY__ -DWIN32 -pipe -O2 -Wall
LDFLAGS		 = -s -lwsock32 -lws2_32 -lwpcap -lpacket
SRC_NAME	 = winpcap_common winarp-sk
LIBS		 = ../WpdPack
EXECUTABLE	 = winarp_sk
SRC_EXT		 = cpp


# targets
all: $(EXECUTABLE)

$(EXECUTABLE): $(patsubst %,%.o,$(SRC_NAME))
	@echo
	$(CXX) $(patsubst %,-L%/lib,$(LIBS)) $(patsubst %,%.o,$(SRC_NAME)) $(LDFLAGS) -o $(EXECUTABLE)
	@echo

$(patsubst %,%.o,$(SRC_NAME)): %.o : %.$(SRC_EXT)
	@echo
	$(CXX) $(CXXFLAGS) $(patsubst %,-I%/include,$(LIBS)) -c $< -o $@

clean:
	@echo
	rm -f $(patsubst %,./%.o,$(SRC_NAME)) ./$(EXECUTABLE).exe
	@echo
