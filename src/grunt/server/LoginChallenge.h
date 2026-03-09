/*
 * Copyright (c) 2015 - 2026 Ember
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#pragma once

#include "../Opcodes.h"
#include "../State.h"
#include "../ResultCodes.h"
#include "hexi/hexi.h"
#include <array>
#include <cstdint>
#include <cstddef>

namespace grunt::server {

class LoginChallenge final {
	static const std::uint8_t wire_length = 119;
	static const std::uint8_t salt_length = 32;

	State state_ = State::initial;

	void read_body(auto& stream) {
		stream >> opcode;
		stream >> protocol_ver;
		stream >> result;

		if(result != grunt::Result::success) {
			state_ = State::done;
			return; // rest of the fields won't be sent
		}

		std::array<std::uint8_t, pub_key_length> b_buff;
		stream >> b_buff;

		stream >> g_len;

		if(g_len > 1) {
			throw bad_packet("invalid generator length");
		}

		stream >> g;
		stream >> n_len;

		std::array<std::uint8_t, prime_length> n_buff;
		stream >> n_buff;
		stream >> salt;
		stream >> checksum_salt;
		stream >> two_factor_auth;

		if(!two_factor_auth) {
			state_ = State::done;
		}
	}

	void read_pin_data(auto& stream) {
		if(state_ == State::done) {
			return;
		}

		// does the stream hold enough bytes to complete the PIN data?
		if(stream.size() >= (pin_salt.size() + sizeof(pin_grid_seed))) {
			stream >> pin_grid_seed;
			stream >> pin_salt;
			state_ = State::done;
		} else {
			state_ = State::call_again;
		}
	}

public:
	LoginChallenge() {};

	static const std::uint8_t prime_length         = 32;
	static const std::uint8_t pub_key_length       = 32;
	static const std::uint8_t pin_salt_length      = 16;
	static const std::uint8_t checksum_salt_length = 16;

	enum class TwoFactorSecurity : std::uint8_t {
		none,
		pin
	};

	Opcode opcode;
	Result result;
	std::uint8_t protocol_ver = 0;
	/*Botan::BigInt B;*/
	std::uint8_t g_len;
	std::uint8_t g;
	std::uint8_t n_len;
	/*Botan::BigInt N;
	Botan::BigInt s;*/
	std::array<std::uint8_t, checksum_salt_length> checksum_salt;
	bool two_factor_auth = false;
	std::uint32_t pin_grid_seed;
	std::array<std::uint8_t, pin_salt_length> pin_salt;
	std::array<std::uint8_t, salt_length> salt;

	// todo - early abort (wire length change)
	State read_from_stream(auto& stream) {
		if(state_ == State::initial && stream.size() < wire_length) {
			return State::call_again;
		}

		switch(state_) {
			case State::initial:
				read_body(stream);
				[[fallthrough]];
			case State::call_again:
				read_pin_data(stream);
				break;
			default:
				std::abort();
		}

		return state_;
	}
};

} // server, grunt