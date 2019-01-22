# variable definitions
CXXFLAGS	+= -Wall -c -fomit-frame-pointer -std=c++0x -O3	\
		  -fno-strict-aliasing -fno-stack-protector	-fPIC\
		  -DBIGARRAY_MULTIPLIER=1 -DUSING_XED		\
		  -DTARGET_IA32E -DHOST_IA32E -DTARGET_LINUX -g 
CXXFLAGS_SO	+= -Wl,--hash-style=sysv -Wl,-Bsymbolic	-shared \
		   -Wl,--version-script=$(PIN_HOME)/source/include/pin/pintool.ver
LIBS		+= -lpin  -lxed -ldwarf -lelf -ldl # -liberty
H_INCLUDE	+= -I. -I$(PIN_HOME)/source/include/pin		\
		   -I$(PIN_HOME)/source/include/pin/gen		\
		   -I$(PIN_HOME)/extras/xed2-intel64/include	\
		   -I$(PIN_HOME)/extras/components/include  
L_INCLUDE	+= -L$(PIN_HOME)/extras/xed2-intel64/lib	\
		-L$(PIN_HOME)/intel64/lib -L$(PIN_HOME)/intel64/lib-ext
OBJS		= func_detect.o
SOBJS		= $(OBJS:.o=.so)

# phony targets
.PHONY: all clean

all: $(SOBJS)

func_detect.so: func_detect.o
	$(CXX) $(CXXFLAGS_SO) $(L_INCLUDE) -o $(@) $(@:.so=.o) $(LIBS)
func_detect.o: func_detect.cpp
	$(CXX) $(CXXFLAGS) $(H_INCLUDE) -o $(@) $(@:.o=.cpp)

# clean
clean:
	rm -rf $(OBJS) $(SOBJS)
