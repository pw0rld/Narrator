# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.13

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
CMAKE_COMMAND = /usr/local/cmake-3.13.1-Linux-x86_64/bin/cmake

# The command to remove a file.
RM = /usr/local/cmake-3.13.1-Linux-x86_64/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/pw0rld/Desktop/sample_test/four/Distributed-TEE-systems-niu/test_demo/Narrator/AE_Client

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/pw0rld/Desktop/sample_test/four/Distributed-TEE-systems-niu/test_demo/Narrator/AE_Client/build

# Utility rule file for enclave_a_signed.

# Include the progress variables for this target.
include enclave/CMakeFiles/enclave_a_signed.dir/progress.make

enclave/CMakeFiles/enclave_a_signed: ../enclave/enclave_a.signed


enclave/enclave_a.signed: enclave/enclave_a
enclave/enclave_a.signed: ../enclave/enc.conf
enclave/enclave_a.signed: enclave/private_a.pem
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --blue --bold --progress-dir=/home/pw0rld/Desktop/sample_test/four/Distributed-TEE-systems-niu/test_demo/Narrator/AE_Client/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Generating enclave_a.signed"
	cd /home/pw0rld/Desktop/sample_test/four/Distributed-TEE-systems-niu/test_demo/Narrator/AE_Client/build/enclave && /opt/openenclave/bin/oesign sign -e /home/pw0rld/Desktop/sample_test/four/Distributed-TEE-systems-niu/test_demo/Narrator/AE_Client/build/enclave/enclave_a -c /home/pw0rld/Desktop/sample_test/four/Distributed-TEE-systems-niu/test_demo/Narrator/AE_Client/enclave/enc.conf -k private_a.pem

enclave/private_a.pem:
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --blue --bold --progress-dir=/home/pw0rld/Desktop/sample_test/four/Distributed-TEE-systems-niu/test_demo/Narrator/AE_Client/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Generating private_a.pem, public_a.pem"
	cd /home/pw0rld/Desktop/sample_test/four/Distributed-TEE-systems-niu/test_demo/Narrator/AE_Client/build/enclave && openssl genrsa -out private_a.pem -3 3072
	cd /home/pw0rld/Desktop/sample_test/four/Distributed-TEE-systems-niu/test_demo/Narrator/AE_Client/build/enclave && openssl rsa -in private_a.pem -pubout -out public_a.pem

enclave/public_a.pem: enclave/private_a.pem
	@$(CMAKE_COMMAND) -E touch_nocreate enclave/public_a.pem

enclave_a_signed: enclave/CMakeFiles/enclave_a_signed
enclave_a_signed: enclave/enclave_a.signed
enclave_a_signed: enclave/private_a.pem
enclave_a_signed: enclave/public_a.pem
enclave_a_signed: enclave/CMakeFiles/enclave_a_signed.dir/build.make

.PHONY : enclave_a_signed

# Rule to build all files generated by this target.
enclave/CMakeFiles/enclave_a_signed.dir/build: enclave_a_signed

.PHONY : enclave/CMakeFiles/enclave_a_signed.dir/build

enclave/CMakeFiles/enclave_a_signed.dir/clean:
	cd /home/pw0rld/Desktop/sample_test/four/Distributed-TEE-systems-niu/test_demo/Narrator/AE_Client/build/enclave && $(CMAKE_COMMAND) -P CMakeFiles/enclave_a_signed.dir/cmake_clean.cmake
.PHONY : enclave/CMakeFiles/enclave_a_signed.dir/clean

enclave/CMakeFiles/enclave_a_signed.dir/depend:
	cd /home/pw0rld/Desktop/sample_test/four/Distributed-TEE-systems-niu/test_demo/Narrator/AE_Client/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/pw0rld/Desktop/sample_test/four/Distributed-TEE-systems-niu/test_demo/Narrator/AE_Client /home/pw0rld/Desktop/sample_test/four/Distributed-TEE-systems-niu/test_demo/Narrator/AE_Client/enclave /home/pw0rld/Desktop/sample_test/four/Distributed-TEE-systems-niu/test_demo/Narrator/AE_Client/build /home/pw0rld/Desktop/sample_test/four/Distributed-TEE-systems-niu/test_demo/Narrator/AE_Client/build/enclave /home/pw0rld/Desktop/sample_test/four/Distributed-TEE-systems-niu/test_demo/Narrator/AE_Client/build/enclave/CMakeFiles/enclave_a_signed.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : enclave/CMakeFiles/enclave_a_signed.dir/depend
