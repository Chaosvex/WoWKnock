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
#include <array>
#include <unordered_map>
#include <print>

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
asio::awaitable<void> send_challenge(asio::ip::tcp::socket& socket, parsed_args& args);
asio::awaitable<grunt::server::LoginChallenge> read_challenge(asio::ip::tcp::socket& socket);
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

asio::awaitable<void> run(asio::io_context& context, parsed_args args) {
	asio::ip::tcp::resolver resolver(context);
	const auto& [r_ec, endpoints] = co_await resolver.async_resolve(
		args.at(argument::host), args.at(argument::port), asio::as_tuple
	);

	if(r_ec) {
		std::println("Unable to resolve hostname");
		co_return;
	}

	asio::ip::tcp::socket socket(context);

	const auto& [ec, _] = co_await asio::async_connect(socket, endpoints, asio::as_tuple);

	if(ec) {
		std::println("Unable to connect to host");
		co_return;
	}

	co_await send_challenge(socket, args);
	auto response = co_await read_challenge(socket);

	switch(response.result) {
		[[fallthrough]];
		case grunt::Result::success:
		case grunt::Result::success_survey:
		{
			std::println(R"(Account "{}" exists or server is not leaking)", args.at(argument::user));

			if(response.two_factor_auth) {
				std::println("Account has 2FA enabled");
			} else {
				std::println("Account does not have 2FA enabled");
			}

			break;
		}
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
		default:
			std::println("Unhandled response code");
			break;
	}

	std::println("Farewell!");
}

asio::awaitable<void> send_challenge(asio::ip::tcp::socket& socket, parsed_args& args) {
	std::vector<std::uint8_t> buffer;
	hexi::buffer_adaptor adaptor(buffer);
	hexi::binary_stream stream(adaptor, hexi::endian::little);

	grunt::client::LoginChallenge c_challenge;
	c_challenge.username = args.at(argument::user);
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
		std::abort();
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
			std::abort();
		}

		adaptor.advance_write(size);
		read_state = s_challenge.read_from_stream(stream);
	} while(read_state == State::call_again);

	if(read_state != State::done) {
		std::println("Challenge reading oopsie, farewell");
		std::abort();
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
