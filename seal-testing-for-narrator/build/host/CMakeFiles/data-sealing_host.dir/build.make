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
CMAKE_SOURCE_DIR = /home/pw0rld/seal-testing-for-narrator

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/pw0rld/seal-testing-for-narrator/build

# Include any dependencies generated for this target.
include host/CMakeFiles/data-sealing_host.dir/depend.make

# Include the progress variables for this target.
include host/CMakeFiles/data-sealing_host.dir/progress.make

# Include the compile flags for this target's objects.
include host/CMakeFiles/data-sealing_host.dir/flags.make

host/datasealing_u.c: ../datasealing.edl
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --blue --bold --progress-dir=/home/pw0rld/seal-testing-for-narrator/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Generating datasealing_u.c, datasealing_u.h, datasealing_args.h"
	cd /home/pw0rld/seal-testing-for-narrator/build/host && /opt/openenclave_0_17/bin/oeedger8r --search-path /opt/openenclave_0_17/include --search-path /opt/openenclave_0_17/include/openenclave/edl/sgx --untrusted --untrusted-dir . /home/pw0rld/seal-testing-for-narrator/host/../datasealing.edl

host/datasealing_u.h: host/datasealing_u.c
	@$(CMAKE_COMMAND) -E touch_nocreate host/datasealing_u.h

host/datasealing_args.h: host/datasealing_u.c
	@$(CMAKE_COMMAND) -E touch_nocreate host/datasealing_args.h

host/CMakeFiles/data-sealing_host.dir/host.cpp.o: host/CMakeFiles/data-sealing_host.dir/flags.make
host/CMakeFiles/data-sealing_host.dir/host.cpp.o: ../host/host.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/pw0rld/seal-testing-for-narrator/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building CXX object host/CMakeFiles/data-sealing_host.dir/host.cpp.o"
	cd /home/pw0rld/seal-testing-for-narrator/build/host && /bin/clang++-10  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/data-sealing_host.dir/host.cpp.o -c /home/pw0rld/seal-testing-for-narrator/host/host.cpp

host/CMakeFiles/data-sealing_host.dir/host.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/data-sealing_host.dir/host.cpp.i"
	cd /home/pw0rld/seal-testing-for-narrator/build/host && /bin/clang++-10 $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/pw0rld/seal-testing-for-narrator/host/host.cpp > CMakeFiles/data-sealing_host.dir/host.cpp.i

host/CMakeFiles/data-sealing_host.dir/host.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/data-sealing_host.dir/host.cpp.s"
	cd /home/pw0rld/seal-testing-for-narrator/build/host && /bin/clang++-10 $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/pw0rld/seal-testing-for-narrator/host/host.cpp -o CMakeFiles/data-sealing_host.dir/host.cpp.s

host/CMakeFiles/data-sealing_host.dir/datasealing_u.c.o: host/CMakeFiles/data-sealing_host.dir/flags.make
host/CMakeFiles/data-sealing_host.dir/datasealing_u.c.o: host/datasealing_u.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/pw0rld/seal-testing-for-narrator/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building C object host/CMakeFiles/data-sealing_host.dir/datasealing_u.c.o"
	cd /home/pw0rld/seal-testing-for-narrator/build/host && /bin/clang-10 $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/data-sealing_host.dir/datasealing_u.c.o   -c /home/pw0rld/seal-testing-for-narrator/build/host/datasealing_u.c

host/CMakeFiles/data-sealing_host.dir/datasealing_u.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/data-sealing_host.dir/datasealing_u.c.i"
	cd /home/pw0rld/seal-testing-for-narrator/build/host && /bin/clang-10 $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/pw0rld/seal-testing-for-narrator/build/host/datasealing_u.c > CMakeFiles/data-sealing_host.dir/datasealing_u.c.i

host/CMakeFiles/data-sealing_host.dir/datasealing_u.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/data-sealing_host.dir/datasealing_u.c.s"
	cd /home/pw0rld/seal-testing-for-narrator/build/host && /bin/clang-10 $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/pw0rld/seal-testing-for-narrator/build/host/datasealing_u.c -o CMakeFiles/data-sealing_host.dir/datasealing_u.c.s

# Object files for target data-sealing_host
data__sealing_host_OBJECTS = \
"CMakeFiles/data-sealing_host.dir/host.cpp.o" \
"CMakeFiles/data-sealing_host.dir/datasealing_u.c.o"

# External object files for target data-sealing_host
data__sealing_host_EXTERNAL_OBJECTS =

host/data-sealing_host: host/CMakeFiles/data-sealing_host.dir/host.cpp.o
host/data-sealing_host: host/CMakeFiles/data-sealing_host.dir/datasealing_u.c.o
host/data-sealing_host: host/CMakeFiles/data-sealing_host.dir/build.make
host/data-sealing_host: /opt/openenclave_0_17/lib/openenclave/host/liboehost.a
host/data-sealing_host: /usr/lib/x86_64-linux-gnu/libcrypto.so
host/data-sealing_host: /usr/lib/x86_64-linux-gnu/libdl.so
host/data-sealing_host: host/CMakeFiles/data-sealing_host.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/pw0rld/seal-testing-for-narrator/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Linking CXX executable data-sealing_host"
	cd /home/pw0rld/seal-testing-for-narrator/build/host && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/data-sealing_host.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
host/CMakeFiles/data-sealing_host.dir/build: host/data-sealing_host

.PHONY : host/CMakeFiles/data-sealing_host.dir/build

host/CMakeFiles/data-sealing_host.dir/clean:
	cd /home/pw0rld/seal-testing-for-narrator/build/host && $(CMAKE_COMMAND) -P CMakeFiles/data-sealing_host.dir/cmake_clean.cmake
.PHONY : host/CMakeFiles/data-sealing_host.dir/clean

host/CMakeFiles/data-sealing_host.dir/depend: host/datasealing_u.c
host/CMakeFiles/data-sealing_host.dir/depend: host/datasealing_u.h
host/CMakeFiles/data-sealing_host.dir/depend: host/datasealing_args.h
	cd /home/pw0rld/seal-testing-for-narrator/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/pw0rld/seal-testing-for-narrator /home/pw0rld/seal-testing-for-narrator/host /home/pw0rld/seal-testing-for-narrator/build /home/pw0rld/seal-testing-for-narrator/build/host /home/pw0rld/seal-testing-for-narrator/build/host/CMakeFiles/data-sealing_host.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : host/CMakeFiles/data-sealing_host.dir/depend

