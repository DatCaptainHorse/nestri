#pragma once

#include <map>
#include <thread>
#include <vector>
#include <format>
#include <chrono>
#include <memory>
#include <utility>
#include <fstream>
#include <filesystem>

#include <inputtino/input.hpp>
#include <jwt-cpp/jwt.h>
#include <jwt-cpp/traits/nlohmann-json/traits.h>
#include <hv/json.hpp>
#include <hv/base64.h>
#include <hv/WebSocketServer.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <fake-udev/fake-udev.hpp>
#include <scn/scan.h>

#include "utils.hpp"

using jsontraits = jwt::traits::nlohmann_json;
using jsonclaim = jwt::basic_claim<jsontraits>;

// TODO: Cleanup by splitting stuff into files

namespace nestri {
	class WSServer {
		std::string m_secret;
		std::string m_sessionToken;
		hv::WebSocketService m_service;
		hv::WebSocketServer m_server;

		std::unique_ptr<inputtino::Mouse> m_mouse = nullptr;
		std::unique_ptr<inputtino::Keyboard> m_keyboard = nullptr;
		std::unique_ptr<inputtino::XboxOneJoypad> m_controller = nullptr;

	public:
		WSServer(std::string secret, const std::int32_t port)
			: m_secret(std::move(secret)), m_server(&m_service) {
			m_service.onopen = [](const WebSocketChannelPtr &channel, const HttpRequestPtr &req) {
				nestri::log("WS OPEN");
			};
			m_service.onmessage = [this](const WebSocketChannelPtr &channel, const std::string &msg) {
				//nestri::log(std::format("WS MSG: {}", msg));
				on_message(channel, msg);
			};
			m_service.onclose = [](const WebSocketChannelPtr &channel) {
				nestri::log("WS CLOSE");
			};

			m_server.setPort(port);
			m_server.setThreadNum(static_cast<std::int32_t>(nestri::get_small_threads_count()));
		}

		void run() {
			m_server.run();
		}

		void prepare_devices() {
			nestri::log("Preparing for devices..");

			nestri::log("Creating directories..");
			std::filesystem::create_directories("/dev/input");
			std::filesystem::create_directories("/run/udev");
			std::filesystem::create_directories("/tmp/nestri/inputs");
			const auto udev_ctrl_path = std::filesystem::path("/run/udev/control");
			if (!std::filesystem::exists(udev_ctrl_path)) {
				if (auto control_file = std::ofstream(udev_ctrl_path)) {
					control_file.close();
					std::filesystem::permissions(udev_ctrl_path, std::filesystem::perms::all);
				}
			}
			nestri::log("Directories created");

			nestri::log("Preparations done");
        }

		auto get_sysfs_path(const std::string &event_str) -> std::filesystem::path {
            std::ifstream file("/proc/bus/input/devices");

            std::filesystem::path sysfs_path;
            std::string temp_path;
            std::string line;
            while (std::getline(file, line)) {
                auto res = scn::scan<std::string>(line, "S: Sysfs={}");
                if (res)
					temp_path = res->value();

                if (!temp_path.empty() && line.contains("Handlers=") && line.contains(event_str)) {
					sysfs_path = temp_path;
					temp_path.clear();
					break;
				}
            }
            return sysfs_path;
        }

        void mknod_input_new(const std::filesystem::path &path) {
			const auto id = std::stoi(nestri::split_substr(path.string(), "/dev/input/event")[1]);
			/*if (std::filesystem::exists(path)) {
				std::error_code ec;
				if (!std::filesystem::remove(path, ec))
					nestri::log(std::format("Failed to remove '{}' - reason: {}", path.string(), ec.message()));
			}*/

			if (!std::filesystem::exists(path)) {
				nestri::log(std::format("New input mknod: {}", path.string()));
			    if (system(std::format("mknod {} c 13 {}", path.string(), id).c_str()) != 0)
			    	nestri::log(std::format("mknod failed: {}", std::strerror(errno)));
			    else if (system(std::format("chmod 777 {}", path.string()).c_str()) != 0)
			    	nestri::log(std::format("chmod failed: {}", std::strerror(errno)));
				else if (system(std::format("chgrp input {}", path.string()).c_str()) != 0)
					nestri::log(std::format("chgrp failed: {}", std::strerror(errno)));
			}
        }

        void fakeudev_add(const std::filesystem::path &path, const std::filesystem::path &devpath) {
			netlink_connection conn{};
            if (connect(conn, AF_NETLINK, SOCK_RAW, NETLINK_KOBJECT_UEVENT, 2)) {
            	const std::string msg
                  = std::format("ACTION=add\0DEVNAME={}\0DEVPATH={}\0SEQNUM=1234\0SUBSYSTEM=input\0",
                                path.string(), devpath.string());
                auto header = make_udev_header(msg, "input", "");
                if (!send_msgs(conn, {header, msg}))
                    nestri::log(std::format("Failed to send add msg"));
            }
            cleanup(conn);
        }

        void symlink_node(const std::filesystem::path &nodepath) {
			if (std::filesystem::exists(nodepath)) {
				std::error_code ec;
				if (!std::filesystem::remove(nodepath, ec))
					nestri::log(std::format("Failed to remove '{}' - reason: {}", nodepath.string(), ec.message()));
			}

			const auto splitted = nestri::split_substr(nodepath, "/dev/input/");
			if (splitted.size() == 2) {
				std::error_code ec;
				std::filesystem::create_symlink(nodepath, std::format("/tmp/nestri/inputs/{}", splitted[1]), ec);
				if (ec)
					nestri::log(std::format("Failed to symlink '{}' - reason: {}", nodepath.string(), ec.message()));
			} else
				nestri::log(std::format("Invalid nodepath for symlinking '{}'", nodepath.string()));
		}

		void handle_nodes(const std::vector<std::string> &nodes) {
			for (const auto &node : nodes) {
				nestri::log(std::format("Node: {}", node));
				mknod_input_new(node);
				const auto splitted = nestri::split_substr(node, "/dev/input/");
				if (splitted.size() == 2) {
					if (const auto dpath = get_sysfs_path(splitted[1]); !dpath.empty()) {
						nestri::log(std::format("Node sysfs: {}", dpath.string()));
						fakeudev_add(node, dpath);
					}
				}
				symlink_node(node);
			}
		}

		void create_mouse() {
			nestri::log("Creating mouse input..");
			auto input_mouse = inputtino::Mouse::create();
			if (!input_mouse) {
				nestri::log(std::format("Failed to create mouse input: {}", input_mouse.getErrorMessage()));
				return;
			}
			m_mouse = std::make_unique<inputtino::Mouse>(std::move(*input_mouse));
			handle_nodes(m_mouse->get_nodes());
			nestri::log("Successfully created mouse input");
		}

		void create_keyboard() {
			nestri::log("Creating keyboard input..");
			auto input_keyboard = inputtino::Keyboard::create();
			if (!input_keyboard) {
				nestri::log(std::format("Failed to create keyboard input: {}", input_keyboard.getErrorMessage()));
				return;
			}
			m_keyboard = std::make_unique<inputtino::Keyboard>(std::move(*input_keyboard));
			handle_nodes(m_keyboard->get_nodes());
			nestri::log("Successfully created keyboard input");
		}

		void create_controller() {
			nestri::log("Creating controller input..");
			auto input_controller = inputtino::XboxOneJoypad::create();
			if (!input_controller) {
				nestri::log(std::format("Failed to create controller input: {}", input_controller.getErrorMessage()));
				return;
			}
			m_controller = std::make_unique<inputtino::XboxOneJoypad>(std::move(*input_controller));
			handle_nodes(m_controller->get_nodes());
			nestri::log("Successfully created controller input");
		}

		void on_message(const WebSocketChannelPtr &ch, const std::string &msg) const {
			const auto json = hv::Json::parse(msg);
			if (!json.contains("type"))
				return;

			const auto type = json["type"].get<std::string>();

			if (json.contains("sessionToken")) {
				const auto incoming_token = json["sessionToken"].get<std::string>();
				if (!verify_session(incoming_token))
					return;

				if (type.starts_with("input_")) {
					const auto input_srckind = nestri::remove_substr(type, "input_");
					const auto input_split = nestri::split_substr(input_srckind, "_");
					if (input_split.size() != 2)
						return;

					const auto &input_device = input_split[0];
					const auto &input_method = input_split[1];

					//nestri::log(std::format("INPUT DEVICE/METHOD: {}/{}", input_device, input_method));

					if (input_device == "mouse") {
						if (input_method == "move" && json.contains("x") && json.contains("y")
							&& json.contains("screenx") && json.contains("screeny")) {
							const auto x = json["x"].get<std::int32_t>();
							const auto y = json["y"].get<std::int32_t>();
							const auto scrx = json["screenx"].get<std::int32_t>();
							const auto scry = json["screeny"].get<std::int32_t>();
							m_mouse->move_abs(x, y, scrx, scry);
						} else if (input_method == "wheel" && json.contains("dx") && json.contains("dy")) {
							const auto dx = json["dx"].get<std::int32_t>();
							const auto dy = json["dy"].get<std::int32_t>();
							m_mouse->horizontal_scroll(dx);
							m_mouse->vertical_scroll(dy);
						} else if (input_method == "up" && json.contains("button")) {
							const auto button = json["button"].get<std::int32_t>();
							// JS button numbers map to inputtino ones straight
							m_mouse->release(static_cast<inputtino::Mouse::MOUSE_BUTTON>(button));
						} else if (input_method == "down" && json.contains("button")) {
							const auto button = json["button"].get<std::int32_t>();
							// JS button numbers map to inputtino ones straight
							m_mouse->press(static_cast<inputtino::Mouse::MOUSE_BUTTON>(button));
						}
					} else if (input_device == "keyboard") {
						if (input_method == "up" && json.contains("key")) {
							const auto key = json["key"].get<std::int32_t>();
							m_keyboard->release(key);
						} else if (input_method == "down" && json.contains("key")) {
							const auto key = json["key"].get<std::int32_t>();
							m_keyboard->press(key);
						}
					} else if (input_device == "controller") {
						nestri::log("Controller input unimplemented");
					}
				}
			} else if (type.contains("jwt_session") && json.contains("secret")) {
				// Compare secrets
				if (hv::Base64Decode(json["secret"].get<std::string>().c_str()) == m_secret) {
					nestri::log("SECRET MATCH - CREATING NEW SESSION TOKEN");
					hv::Json response;
					response["type"] = "jwt_session";
					response["sessionToken"] = create_new_token();
					ch->send(response.dump());
				}
			}
		}

		auto verify_session(const std::string &token) const -> bool {
			try {
				const auto decoded = jwt::decode<jsontraits>(token);
				jwt::verify<jsontraits>()
						.allow_algorithm(jwt::algorithm::hs256(m_secret))
						.with_type("JWT")
						.with_issuer("nestri.io")
						.with_audience("nestri.io")
						.verify(decoded);

				//nestri::log("VERIFIED TOKEN");
				return true;
			} catch (const std::exception &e) {
				nestri::log(std::format("COULD NOT VERIFY TOKEN - REASON: {}", e.what()));
			}
			return false;
		}

		auto create_new_token() const -> std::string {
			const auto time = jwt::date::clock::now();
			return jwt::create<jsontraits>()
					.set_type("JWT")
					.set_issuer("nestri.io")
					.set_audience("nestri.io")
					.set_issued_at(time)
					.set_not_before(time)
					.set_expires_at(time + std::chrono::minutes(30))
					.sign(jwt::algorithm::hs256(m_secret));
		}
	};
}
