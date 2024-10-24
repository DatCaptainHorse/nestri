module;

#include <format>
#include <chrono>
#include <memory>
#include <utility>

#include <inputtino/input.hpp>
#include <jwt-cpp/jwt.h>
#include <jwt-cpp/traits/danielaparker-jsoncons/traits.h>
#include <hv/json.hpp>
#include <hv/base64.h>
#include <hv/WebSocketServer.h>

export module wsserver;

import utilities;

using jsontraits = jwt::traits::danielaparker_jsoncons;
using jsonclaim = jwt::basic_claim<jsontraits>;

export namespace nestri {
	class WSServer {
		std::string m_secret;
		std::string m_sessionToken;
		hv::WebSocketService m_service;
		hv::WebSocketServer m_server;

		std::unique_ptr<inputtino::Mouse> m_mouse = nullptr;

	public:
		WSServer(std::string secret, const std::int32_t port)
			: m_secret(std::move(secret)), m_server(&m_service) {
			m_service.onopen = [](const WebSocketChannelPtr &channel, const HttpRequestPtr &req) {
				nestri::log("WS OPEN");
			};
			m_service.onmessage = [this](const WebSocketChannelPtr &channel, const std::string &msg) {
				nestri::log(std::format("WS MSG: {}", msg));
				on_message(channel, msg);
			};
			m_service.onclose = [](const WebSocketChannelPtr &channel) {
				nestri::log("WS CLOSE");
			};

			m_server.setPort(port);
			m_server.setThreadNum(static_cast<std::int32_t>(nestri::get_small_threads_count()));
		}

		void run() {
			nestri::log("oofR");
			m_server.run();
			nestri::log("oofRE");
		}

		void attach_mouse() {
			nestri::log("Attaching mouse..");
			auto input_mouse = inputtino::Mouse::create();
			if (!input_mouse) {
				nestri::log("FAILED TO CREATE INPUT MOUSE");
				nestri::log(std::format("Failed to create mouse input: {}", input_mouse.getErrorMessage()));
				return;
			}
			nestri::log("Successfully created mouse input");
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

					nestri::log(std::format("INPUT DEVICE/METHOD: {}/{}", input_device, input_method));

					if (input_device == "mouse" && input_method == "move" && json.contains("x") && json.contains("y")) {
						const auto x = json["x"].get<std::int32_t>();
						const auto y = json["y"].get<std::int32_t>();
						m_mouse->move_abs(x, y, 1280, 720);
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

				nestri::log("VERIFIED TOKEN");
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
