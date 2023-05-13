# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.16

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/jetli/sgx-learning/project/SGX_BRAFT/openenclave_0.17.0/samples/data-sealing

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/jetli/sgx-learning/project/SGX_BRAFT/openenclave_0.17.0/samples/data-sealing/build

# Include any dependencies generated for this target.
include enclave_a_v2/CMakeFiles/enclave_a_v2.dir/depend.make

# Include the progress variables for this target.
include enclave_a_v2/CMakeFiles/enclave_a_v2.dir/progress.make

# Include the compile flags for this target's objects.
include enclave_a_v2/CMakeFiles/enclave_a_v2.dir/flags.make

enclave_a_v2/CMakeFiles/enclave_a_v2.dir/ecalls.cpp.o: enclave_a_v2/CMakeFiles/enclave_a_v2.dir/flags.make
enclave_a_v2/CMakeFiles/enclave_a_v2.dir/ecalls.cpp.o: ../enclave_a_v2/ecalls.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/jetli/sgx-learning/project/SGX_BRAFT/openenclave_0.17.0/samples/data-sealing/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object enclave_a_v2/CMakeFiles/enclave_a_v2.dir/ecalls.cpp.o"
	cd /home/jetli/sgx-learning/project/SGX_BRAFT/openenclave_0.17.0/samples/data-sealing/build/enclave_a_v2 && /usr/bin/clang++-10  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/enclave_a_v2.dir/ecalls.cpp.o -c /home/jetli/sgx-learning/project/SGX_BRAFT/openenclave_0.17.0/samples/data-sealing/enclave_a_v2/ecalls.cpp

enclave_a_v2/CMakeFiles/enclave_a_v2.dir/ecalls.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/enclave_a_v2.dir/ecalls.cpp.i"
	cd /home/jetli/sgx-learning/project/SGX_BRAFT/openenclave_0.17.0/samples/data-sealing/build/enclave_a_v2 && /usr/bin/clang++-10 $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/jetli/sgx-learning/project/SGX_BRAFT/openenclave_0.17.0/samples/data-sealing/enclave_a_v2/ecalls.cpp > CMakeFiles/enclave_a_v2.dir/ecalls.cpp.i

enclave_a_v2/CMakeFiles/enclave_a_v2.dir/ecalls.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/enclave_a_v2.dir/ecalls.cpp.s"
	cd /home/jetli/sgx-learning/project/SGX_BRAFT/openenclave_0.17.0/samples/data-sealing/build/enclave_a_v2 && /usr/bin/clang++-10 $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/jetli/sgx-learning/project/SGX_BRAFT/openenclave_0.17.0/samples/data-sealing/enclave_a_v2/ecalls.cpp -o CMakeFiles/enclave_a_v2.dir/ecalls.cpp.s

# Object files for target enclave_a_v2
enclave_a_v2_OBJECTS = \
"CMakeFiles/enclave_a_v2.dir/ecalls.cpp.o"

# External object files for target enclave_a_v2
enclave_a_v2_EXTERNAL_OBJECTS = \
"/home/jetli/sgx-learning/project/SGX_BRAFT/openenclave_0.17.0/samples/data-sealing/build/common/CMakeFiles/common.dir/dispatcher.cpp.o" \
"/home/jetli/sgx-learning/project/SGX_BRAFT/openenclave_0.17.0/samples/data-sealing/build/common/CMakeFiles/common.dir/datasealing_t.c.o"

enclave_a_v2/enclave_a_v2: enclave_a_v2/CMakeFiles/enclave_a_v2.dir/ecalls.cpp.o
enclave_a_v2/enclave_a_v2: common/CMakeFiles/common.dir/dispatcher.cpp.o
enclave_a_v2/enclave_a_v2: common/CMakeFiles/common.dir/datasealing_t.c.o
enclave_a_v2/enclave_a_v2: enclave_a_v2/CMakeFiles/enclave_a_v2.dir/build.make
enclave_a_v2/enclave_a_v2: /opt/openenclave_0_17/lib/openenclave/enclave/objects-Debug/oeseal_gcmaes/seal_gcmaes.c.o
enclave_a_v2/enclave_a_v2: /opt/openenclave_0_17/lib/openenclave/enclave/liboeenclave.a
enclave_a_v2/enclave_a_v2: /opt/openenclave_0_17/lib/openenclave/enclave/liboecryptombedtls.a
enclave_a_v2/enclave_a_v2: /opt/openenclave_0_17/lib/openenclave/enclave/libmbedtls.a
enclave_a_v2/enclave_a_v2: /opt/openenclave_0_17/lib/openenclave/enclave/libmbedx509.a
enclave_a_v2/enclave_a_v2: /opt/openenclave_0_17/lib/openenclave/enclave/libmbedcrypto.a
enclave_a_v2/enclave_a_v2: /opt/openenclave_0_17/lib/openenclave/enclave/liboelibcxx.a
enclave_a_v2/enclave_a_v2: /opt/openenclave_0_17/lib/openenclave/enclave/liboelibc.a
enclave_a_v2/enclave_a_v2: /opt/openenclave_0_17/lib/openenclave/enclave/liboesyscall.a
enclave_a_v2/enclave_a_v2: /opt/openenclave_0_17/lib/openenclave/enclave/liboecore.a
enclave_a_v2/enclave_a_v2: enclave_a_v2/CMakeFiles/enclave_a_v2.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/jetli/sgx-learning/project/SGX_BRAFT/openenclave_0.17.0/samples/data-sealing/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable enclave_a_v2"
	cd /home/jetli/sgx-learning/project/SGX_BRAFT/openenclave_0.17.0/samples/data-sealing/build/enclave_a_v2 && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/enclave_a_v2.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
enclave_a_v2/CMakeFiles/enclave_a_v2.dir/build: enclave_a_v2/enclave_a_v2

.PHONY : enclave_a_v2/CMakeFiles/enclave_a_v2.dir/build

enclave_a_v2/CMakeFiles/enclave_a_v2.dir/clean:
	cd /home/jetli/sgx-learning/project/SGX_BRAFT/openenclave_0.17.0/samples/data-sealing/build/enclave_a_v2 && $(CMAKE_COMMAND) -P CMakeFiles/enclave_a_v2.dir/cmake_clean.cmake
.PHONY : enclave_a_v2/CMakeFiles/enclave_a_v2.dir/clean

enclave_a_v2/CMakeFiles/enclave_a_v2.dir/depend:
	cd /home/jetli/sgx-learning/project/SGX_BRAFT/openenclave_0.17.0/samples/data-sealing/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/jetli/sgx-learning/project/SGX_BRAFT/openenclave_0.17.0/samples/data-sealing /home/jetli/sgx-learning/project/SGX_BRAFT/openenclave_0.17.0/samples/data-sealing/enclave_a_v2 /home/jetli/sgx-learning/project/SGX_BRAFT/openenclave_0.17.0/samples/data-sealing/build /home/jetli/sgx-learning/project/SGX_BRAFT/openenclave_0.17.0/samples/data-sealing/build/enclave_a_v2 /home/jetli/sgx-learning/project/SGX_BRAFT/openenclave_0.17.0/samples/data-sealing/build/enclave_a_v2/CMakeFiles/enclave_a_v2.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : enclave_a_v2/CMakeFiles/enclave_a_v2.dir/depend

