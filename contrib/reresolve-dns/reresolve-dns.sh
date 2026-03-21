#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Copyright (C) 2015-2020 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.

# This script was modified by Orwa Diraneyya specifically for being used on a modern
# Mac OS X system as a cronjob using something like:
# * * * *	SUDO_ASKPASS="$HOME"/.config/askpass sudo -A \
#	PATH="$PATH:/opt/homebrew/bin" DEBUG=1 \
#   "$HOME"/.config/wireguard/reresolve-dns.sh \
#	/opt/homebrew/etc/wireguard/wgX.conf utunX \
#	>>/tmp/wireguard.log 2>/tmp/wireguard.debug || \
#		cp /tmp/wireguard.debug /tmp/wireguard.debug."$?"

if [ -n "$DEBUG" ]; then 
	set -x
	BASH_XTRACEFD=2
	# Append useful information to the end of the xtrace log when debugging
	trap "set +x; printf 'PATH=%s\n' \"$PATH\" >&2; id >&2; date >&2" EXIT
fi

set -e
shopt -s nocasematch
shopt -s extglob
export LC_ALL=C

# Fix for bash 3.2
if [ -z "$EPOCHSECONDS" ]; then
	EPOCHSECONDS=$(date +'%s')
fi

show_usage() {
	if [ -t 1 ]; then
		printf "%sUSAGE:%s %s <config-file> [<interface>]%s\n" \
			"$(tput smul)$(tput setaf 2)" "$(tput rmul)" \
			"$(basename "$0")" "$(tput sgr0)"
		if [ -n "$INTERFACE" ]; then
			printf "%s(Note that in your invocation, <interface> was set to '$INTERFACE')%s\n" \
				"$(tput dim)$(tput setaf 7)" "$(tput sgr0)"
		fi
	else
		printf "ERROR: %s %s (%s)\n" "$(basename "$0")" "$*" "$(date)"
	fi
}

CONFIG_FILE="$1"
if ! [ -f "$CONFIG_FILE" ]; then 
	show_usage "$@"
	exit 2
fi 

[[ $CONFIG_FILE =~ ^[a-zA-Z0-9_=+.-]{1,15}$ ]] && CONFIG_FILE="/etc/wireguard/$CONFIG_FILE.conf"
[[ $CONFIG_FILE =~ /?([a-zA-Z0-9_=+.-]{1,15})\.conf$ ]]

INTERFACE="${BASH_REMATCH[1]}"
INTERFACE="${2:-$INTERFACE}"

process_peer() {
	# Only process peer sections in the configuration, a non-peer section is skipped without erroring
	[[ "$PEER_SECTION" -ne 1 ]] && return 0
	[ -z "$PUBLIC_KEY" ] && return 3
	[ -z "$ENDPOINT"   ] && return 4
	LATEST_HANDSHAKE="$(wg show "$INTERFACE" latest-handshakes || true)"
	[[ "$LATEST_HANDSHAKE" =~ ${PUBLIC_KEY//+/\\+}\	([0-9]+) ]] || return 5
	DISCONNECT_DURATION=$(($EPOCHSECONDS - ${BASH_REMATCH[1]}))
	[[ "$DISCONNECT_DURATION" =~ ^[0-9]+$ ]] || return 6
	[ "$DISCONNECT_DURATION" -gt 135 ] || return 0

	wg set "$INTERFACE" peer "$PUBLIC_KEY" endpoint "$ENDPOINT"
	if ! [ -t 1 ]; then
		printf "HANDSHAKE ABSENT FOR %s SECONDS: RE-RESOLVING ENDPOINT '%s'\n" \
			"$DISCONNECT_DURATION" "$ENDPOINT"
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
	[[ $key == "["* ]] && { 
		process_peer || {
			EXIT_CODE=$?
			show_usage "$@"
			exit $EXIT_CODE
		}
		reset_peer_section; 
	}
	[[ $key == "[Peer]" ]] && PEER_SECTION=1
	if [[ $PEER_SECTION -eq 1 ]]; then
		case "$key" in
		PublicKey) PUBLIC_KEY="$value"; continue ;;
		Endpoint) ENDPOINT="$value"; continue ;;
		esac
	fi
done < "$CONFIG_FILE"

process_peer || {
    EXIT_CODE=$?
    show_usage "$@"
    exit $EXIT_CODE
}

