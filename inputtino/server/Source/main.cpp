#include <format>
#include <memory>

#include "server.hpp"
#include "utils.hpp"

constexpr std::int32_t DEFAULT_PORT = 8998;
constexpr auto DEFAULT_SECRET = "test-secret-1234";

auto main(const int argc, char *argv[]) -> int {
	// Get passed args
	const auto program_args = nestri::parse_program_args(argc, argv);

	std::string secret = DEFAULT_SECRET;
	if (program_args.contains("secret")) {
		if (const auto arg_secret = program_args.at("secret"); !arg_secret.empty())
			secret = arg_secret;
		else {
			nestri::log("Error: Given secret parameter value is empty");
			return 1;
		}
	}

	std::int32_t port = DEFAULT_PORT;
	if (program_args.contains("port")) {
		try {
			port = std::stoi(program_args.at("port"));
		} catch (const std::exception &e) {
			nestri::log(std::format("Error: Could not convert port parameter value into integer: {}", e.what()));
			return 1;
		}
	}

	// Start server
	nestri::log(std::format("Starting Nestri WebSocket input server on port: {}", port));
	const auto wss = std::make_unique<nestri::WSServer>(secret, port);

	wss->prepare_devices();
	wss->create_mouse();
	wss->create_keyboard();
	//wss->create_controller();
	wss->run();

	nestri::log("Nestri WebSocket input server exiting..");

	return 0;
}
