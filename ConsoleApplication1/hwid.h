#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include <ostream>
#include <fstream>
#include <sstream>
#include <intrin.h>


namespace get_hwid {
	std::string get_comp_username(bool User);
	std::string get_hwuid();
	std::string get_cpuid();
	DWORD get_volimeid();
	std::string string_to_hex(const std::string input);
	std::string get_hwidkey();
	std::string get_hash_text(const void* data, const size_t data_size);
	std::string get_hash_serial_key();
	std::string get_hash_cpuid();
	std::string hwid();
}