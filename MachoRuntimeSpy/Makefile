SOURCES = $(wildcard *.cpp)

# OSX macOS
ifeq ($(MAC_GCC_UNIVERSAL),)
# $(CURDIR)/build/include
MAC_INCLUDE_DIR = $(abspath thirdparty/readline/mac/include)
# $(CURDIR)/build/lib
MAC_LIB_DIR = $(abspath thirdparty/readline/mac/lib)
MAC_CFLAGS =
# http://hanjianwei.com/2013/01/27/abi-compatibility-between-c-plus-plus-11-and-c-plus-plus-98/
MAC_CXXFLAGS = $(MAC_CFLAGS) -I$(MAC_INCLUDE_DIR) -stdlib=libc++ -std=c++11 -O0 -gmodules
MAC_LDFLAGS = -L$(MAC_LIB_DIR)
MAC_LIBS = -lreadline -lncurses
MAC_GCC_BIN = `xcrun --sdk macosx --find clang++`
MAC_SDK = `xcrun --sdk macosx --show-sdk-path`
MAC_GCC_BASE = $(MAC_GCC_BIN) -g $(MAC_CXXFLAGS) $(MAC_LDFLAGS) $(MAC_LIBS) -isysroot $(MAC_SDK)
export MAC_GCC_UNIVERSAL = $(MAC_GCC_BASE) -arch x86_64
endif

# IOS
ifeq ($(IOS_GCC_UNIVERSAL),)
IOS_INCLUDE_DIR = $(abspath thirdparty/readline/ios/include)
IOS_LIB_DIR = $(abspath thirdparty/readline/ios/lib)

IOS_CFLAGS =
# http://hanjianwei.com/2013/01/27/abi-compatibility-between-c-plus-plus-11-and-c-plus-plus-98/
IOS_CXXFLAGS = $(IOS_CFLAGS) -I$(IOS_INCLUDE_DIR) -stdlib=libc++ -std=c++11 -O0 -gmodules
IOS_LDFLAGS = -L$(IOS_LIB_DIR)
IOS_LIBS = -lreadline -lncurses
IOS_GCC_BIN = `xcrun --sdk iphoneos --find clang++`
IOS_SDK = `xcrun --sdk iphoneos --show-sdk-path`
IOS_GCC_BASE=$(IOS_GCC_BIN) -g $(IOS_CXXFLAGS) $(IOS_LDFLAGS) $(IOS_LIBS) -Wimplicit -isysroot $(IOS_SDK)
export IOS_GCC_UNIVERSAL = $(IOS_GCC_BASE) -arch armv7 -arch arm64
endif

# output directories

all:
	@echo $(MAC_GCC_UNIVERSAL)
	@echo $(CURDIR)/build/include

mac:
	mkdir -p output/
	@echo $(MAC_GCC_UNIVERSAL) $(SOURCES) -o rtspy-mac
	@$(MAC_GCC_UNIVERSAL) $(SOURCES) -o rtspy-mac
	@cp rtspy-mac output/rtspy-mac
	# @echo start ldid...
	# @ldid -Sent.xml rtspy-mac

ios:
	mkdir -p output/
	@echo $(IOS_GCC_UNIVERSAL) $(SOURCES) -o rtspy-ios
	@$(IOS_GCC_UNIVERSAL) $(SOURCES) -o rtspy-ios
	@cp rtspy-ios output/rtspy-ios
	# @echo start ldid...
	# @ldid -Sent.xml rtspy-ios
	# @echo ldid done.

