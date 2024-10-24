#pragma once

#include <map>
#include <format>
#include <thread>
#include <string>
#include <vector>
#include <random>
#include <iostream>
#include <algorithm>
#include <string_view>
#include <source_location>

namespace nestri {
	// Returns up to 8 threads, unless there's the system lacks threads, 1 is returned, never returns 0.
	auto get_small_threads_count() -> std::uint32_t {
		return std::clamp<std::uint32_t>(std::thread::hardware_concurrency(), 1, 8) / 2;
	}

	// Logs message to stdout, with source location
	auto log(std::string_view message, const std::source_location &loc = std::source_location::current()) -> void {
		std::cout << std::format("[{}:{}] {}\n", loc.file_name(), loc.line(), message);
	}

	// Returns string with substring removed
	auto remove_substr(const std::string &str, const std::string &substr) -> std::string {
		std::string result = str;
		size_t pos = result.find(substr);
		while (pos != std::string::npos) {
			result.erase(pos, substr.length());
			pos = result.find(substr, pos);
		}
		return result;
	}

	// Splits string into multiple parts by substring
	auto split_substr(const std::string &str, const std::string &substr) -> std::vector<std::string> {
		std::vector<std::string> tokens;
		size_t pos = 0;
		size_t prevPos = 0;
		while ((pos = str.find(substr, prevPos)) != std::string::npos) {
			tokens.push_back(str.substr(prevPos, pos - prevPos));
			prevPos = pos + substr.length();
		}
		if (prevPos < str.length())
			tokens.push_back(str.substr(prevPos));

		return tokens;
	}

	// Parses program arguments into key-value map
	auto parse_program_args(const int argc, char *argv[]) -> std::map<std::string, std::string> {
		std::map<std::string, std::string> args;
		for (int i = 1; i < argc; ++i) {
			if (std::string arg = argv[i]; arg.length() > 2 && arg[0] == '-') {
				if (std::string key = arg.substr(1); key.length() > 0 && key[0] != '-') {
					if (i + 1 < argc && argv[i + 1][0] != '-') {
						args[key] = argv[i + 1];
						++i;
					} else
						args[key] = "";
				}
			}
		}
		return args;
	}
}
