#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Copyright (C) 2015-2020 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.

set -e
shopt -s nocasematch
shopt -s extglob
export LC_ALL=C

show_usage() {
	if [ -t 1 ]; then
		printf "%sUSAGE:%s %s <config-file> [<interface>]%s\n" \
			"$(tput smul)$(tput setaf 3)" "$(tput rmul)" \
			"$(basename "$0")" "$(tput sgr0)"
		if [ -n "$INTERFACE" ]; then
			printf "%s(Note that in your invocation, <interface> was set to '$INTERFACE')%s\n" \
				"$(tput dim)$(tput setaf 3)" "$(tput sgr0)"
		fi
	else
		printf "ERROR: %s\n" "$0"
	fi
	exit 0
}

CONFIG_FILE="$1"
[[ $CONFIG_FILE =~ ^[a-zA-Z0-9_=+.-]{1,15}$ ]] && CONFIG_FILE="/etc/wireguard/$CONFIG_FILE.conf"
[[ $CONFIG_FILE =~ /?([a-zA-Z0-9_=+.-]{1,15})\.conf$ ]]

if ! [ -f "$CONFIG_FILE" ]; then show_usage; fi 

INTERFACE="${BASH_REMATCH[1]}"
INTERFACE="${2:-$INTERFACE}"

process_peer() {
	[[ $PEER_SECTION -ne 1 || -z $PUBLIC_KEY || -z $ENDPOINT ]] && return 0
	LATEST_HANDSHAKE="$(wg show "$INTERFACE" latest-handshakes 2>/dev/null || true)"
	if [ -z "$LATEST_HANDSHAKE" ]; then show_usage; fi 
	[[ "$LATEST_HANDSHAKE" =~ ${PUBLIC_KEY//+/\\+}\	([0-9]+) ]] || return 0
	(( ($EPOCHSECONDS - ${BASH_REMATCH[1]}) > 135 )) || return 0
	wg set "$INTERFACE" peer "$PUBLIC_KEY" endpoint "$ENDPOINT"
	if ! [ -t 1 ]; then
		printf "HANDSHAKES STOPPED: RE-RESOLVING ENDPOINT '%s'\n" "$ENDPOINT"
	fi
	reset_peer_section
}

reset_peer_section() {
	PEER_SECTION=0
	PUBLIC_KEY=""
	ENDPOINT=""
}

reset_peer_section
while read -r line || [[ -n $line ]]; do
	stripped="${line%%\#*}"
	key="${stripped%%=*}"; key="${key##*([[:space:]])}"; key="${key%%*([[:space:]])}"
	value="${stripped#*=}"; value="${value##*([[:space:]])}"; value="${value%%*([[:space:]])}"
	[[ $key == "["* ]] && { process_peer; reset_peer_section; }
	[[ $key == "[Peer]" ]] && PEER_SECTION=1
	if [[ $PEER_SECTION -eq 1 ]]; then
		case "$key" in
		PublicKey) PUBLIC_KEY="$value"; continue ;;
		Endpoint) ENDPOINT="$value"; continue ;;
		esac
	fi
done < "$CONFIG_FILE"
process_peer
