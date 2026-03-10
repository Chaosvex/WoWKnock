#include "grunt/client/LoginChallenge.h"
#include "grunt/server/LoginChallenge.h"
#include "hexi/hexi.h"
#include <asio/io_context.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/as_tuple.hpp>
#include <asio/connect.hpp>
#include <asio/read.hpp>
#include <asio/write.hpp>
#include <asio/ip/tcp.hpp>
#include <algorithm>
#include <array>
#include <string>
#include <string_view>
#include <unordered_map>
#include <print>
#include <cstdlib>
#include <ctime>

using namespace std::literals;

enum class argument {
	user,
	host,
	port
};

struct option {
	std::string_view cmd, help;
};

using parsed_args = std::unordered_map<argument, std::string_view>;

const std::unordered_map<argument, option> params {
	{ argument::user, {"-user", "the username to check" }},
	{ argument::host, {"-host", "server hostname or IP" }},
	{ argument::port, {"-port", "server port"           }}
};

asio::awaitable<void> run(asio::io_context& context, parsed_args args);
asio::awaitable<void> send_challenge(asio::ip::tcp::socket& socket, const std::string_view user);
asio::awaitable<grunt::server::LoginChallenge> read_challenge(asio::ip::tcp::socket& socket);

asio::awaitable<grunt::server::LoginChallenge> query(
	asio::io_context& context, const std::string_view host, const std::string_view port, const std::string_view user
);

asio::awaitable<bool> detect_mitigations(
	asio::io_context& context, const std::string_view host, const std::string_view port
);

parsed_args parse_arguments(const char* argv[]);
void help();

int main(const int argc, const char* argv[]) {
	if(argc < 2) {
		std::println("Missing arguments, use -h");
		return EXIT_FAILURE;
	}

	const auto args = parse_arguments(argv);
	
	asio::io_context context;
	asio::co_spawn(context, run(context, args), asio::detached);
	context.run();
}

asio::awaitable<bool> detect_mitigations(asio::io_context& context,
                                         const std::string_view host,
                                         const std::string_view port) {
	// okay, not the best randomness but whatever
	std::srand(std::time(0));

	const auto random = [] {
		const char charset[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
		const size_t max_index = (sizeof(charset) - 1);
		return charset[std::rand() % max_index];
	};
	
	std::string user(16, 0);
	std::generate_n(user.begin(), user.size(), random);

	auto response = co_await query(context, host, port, user);
	bool mitigating = false;

	if(response.result == grunt::Result::fail_unknown_account) {
		std::println("Server is not mitigating");
	} else if(response.result == grunt::Result::success
			  || response.result == grunt::Result::success_survey) {
		std::println("Server is most likely mitigating, trying again...");
		mitigating = true;
	} else {
		std::println("Unhandled result, continuing anyway...");
	}

	if(mitigating) {
		const auto prev_salt = response.salt;
		auto response = co_await query(context, host, port, user);

		if(response.result == grunt::Result::success
		   || response.result == grunt::Result::success_survey) {
			if(prev_salt != response.salt) {
				std::println("Server is mitigating but is still leaking");
				mitigating = false;
			} else {
				std::println("Server appears to be correctly mitigating (or unknown salt generation method)");
			}
		} else {
			std::print("Server returned a different result. Weird. Steaming on ahead...");
		}
	}

	co_return mitigating;
}

asio::awaitable<void> run(asio::io_context& context, parsed_args args) {
	const auto host = args.at(argument::host);
	const auto port = args.at(argument::port);
	const bool mitigating = co_await detect_mitigations(context, host, port);

	const auto user = args.at(argument::user);
	auto response = co_await query(context, host, port, user);
	bool query_again = false;

	switch(response.result) {
		case grunt::Result::success_survey:
		case grunt::Result::success:
			query_again = true;
			break;
		case grunt::Result::fail_unknown_account:
			std::println(R"(Account "{}" does not exist)", args.at(argument::user));
			break;
		[[fallthrough]];
		case grunt::Result::fail_version_invalid:
		case grunt::Result::fail_version_update:
			std::println("Game version rejected");
			break;
		case grunt::Result::fail_db_busy:
			std::println("Login was unable to process the request");
			break;
		case grunt::Result::fail_banned:
			std::println("Account found and is banned");
			break;
		default:
			std::println("Unhandled response code, {}" , (int)response.result);
			break;
		}

	if(!query_again) {
		std::exit(EXIT_SUCCESS);
	}

	const auto prev_salt = response.salt;
	const auto prev_result = response.result;

	response = co_await query(context, host, port, user);

	if(response.result != prev_result) {
		std::print("Server returned a different result. Is it intoxicated or not returning our calls?");
		std::exit(EXIT_SUCCESS);
	}

	if(response.salt == prev_salt) {
		std::println(R"(Account "{}" exists {})", args.at(argument::user),
			mitigating? "but is likely a false positive" : "and is likely a true positive");

		if(response.two_factor_auth) {
			std::println("Account has 2FA enabled");
		} else {
			std::println("Account does not have 2FA enabled");
		}
	} else {
		std::println(R"(Account "{}" does not exist and the server tried to trick us)", args.at(argument::user));
	}

	std::println("Farewell!");
	std::exit(EXIT_SUCCESS);
}

asio::awaitable<grunt::server::LoginChallenge> query(asio::io_context& context,
                                                     const std::string_view host,
                                                     const std::string_view port,
                                                     const std::string_view user) {
	asio::ip::tcp::resolver resolver(context);

	const auto& [r_ec, endpoints] = co_await resolver.async_resolve(host, port, asio::as_tuple);

	if(r_ec) {
		std::println("Unable to resolve hostname");
		std::exit(EXIT_FAILURE);
	}

	asio::ip::tcp::socket socket(context);

	const auto& [ec, _] = co_await asio::async_connect(socket, endpoints, asio::as_tuple);

	if(ec) {
		std::println("Unable to connect to host");
		std::exit(EXIT_FAILURE);
	}

	co_await send_challenge(socket, user);
	co_return co_await read_challenge(socket);
}

asio::awaitable<void> send_challenge(asio::ip::tcp::socket& socket, const std::string_view user) {
	std::vector<std::uint8_t> buffer;
	hexi::buffer_adaptor adaptor(buffer);
	hexi::binary_stream stream(adaptor, hexi::endian::little);

	grunt::client::LoginChallenge c_challenge;
	c_challenge.username = user;
	c_challenge.game = Game::WoW;

	const GameVersion version{
		.major = 1,
		.minor = 12,
		.patch = 1,
		.build = 5875,
	};

	c_challenge.version = version;
	c_challenge.protocol_ver = 3;
	c_challenge.write_to_stream(stream);

	auto [ec, _]= co_await asio::async_write(socket, asio::buffer(buffer), asio::as_tuple);

	if(ec) {
		std::println("Encountered an error while sending challenge");
		std::exit(EXIT_FAILURE);
	}
}

asio::awaitable<grunt::server::LoginChallenge> read_challenge(asio::ip::tcp::socket& socket) {
	std::array<std::uint8_t, 1024> buffer;
	hexi::buffer_adaptor adaptor(buffer);
	hexi::binary_stream stream(adaptor, hexi::endian::little);

	grunt::server::LoginChallenge s_challenge;
	State read_state = State::initial;

	do {
		auto [ec, size] = co_await socket.async_receive(asio::buffer(buffer), asio::as_tuple);

		if(ec) {
			std::println("Encountered an error while reading challenge");
			std::exit(EXIT_FAILURE);
		}

		adaptor.advance_write(size);
		read_state = s_challenge.read_from_stream(stream);
	} while(read_state == State::call_again);

	if(read_state != State::done) {
		std::println("Challenge reading oopsie, farewell");
		std::exit(EXIT_FAILURE);
	}
	
	co_return s_challenge;
}

void help() {
	for (const auto& [arg, option] : params) {
		std::println("{}, {}", option.cmd, option.help);
	}
}

parsed_args parse_arguments(const char* argv[]) {
	parsed_args args;

	for(auto i = 0u;; ++i) {
		if(!argv[i]) {
			break;
		}

		if(argv[i] == "-h"sv) {
			help();
			std::exit(EXIT_SUCCESS);
		}

		if(!argv[i + 1]) {
			break;
		}

		for(const auto& [arg, option] : params) {
			if(argv[i] == option.cmd) {
				args[arg] = argv[++i];
			}
		}
	}

	return args;
}
