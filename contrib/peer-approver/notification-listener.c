#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <netlink/netlink.h>
#include <netlink/socket.h>
#include <netlink/msg.h>
#include <netlink/attr.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "../../src/uapi/linux/linux/wireguard.h"

#define prerr(...) fprintf(stderr, "Error: " __VA_ARGS__)

#define WG_KEY_LEN 32
#define WG_KEY_LEN_BASE64 ((((WG_KEY_LEN) + 2) / 3) * 4 + 1)

static struct nl_sock *sk = NULL;
static char **cb_argv;
static int cb_argc;

static int cleanup_and_exit(int ret)
{
	if (sk != NULL)
		nl_socket_free(sk);
	exit(ret);
}

static void signal_handler(int sig)
{
	cleanup_and_exit(EXIT_SUCCESS);
}

static inline void encode_base64(char dest[static 4], const uint8_t src[static 3])
{
	const uint8_t input[] = { (src[0] >> 2) & 63, ((src[0] << 4) | (src[1] >> 4)) & 63, ((src[1] << 2) | (src[2] >> 6)) & 63, src[2] & 63 };

	for (unsigned int i = 0; i < 4; ++i)
		dest[i] = input[i] + 'A'
		          + (((25 - input[i]) >> 8) & 6)
		          - (((51 - input[i]) >> 8) & 75)
		          - (((61 - input[i]) >> 8) & 15)
		          + (((62 - input[i]) >> 8) & 3);

}

void key_to_base64(char base64[static WG_KEY_LEN_BASE64], const uint8_t key[static WG_KEY_LEN])
{
	unsigned int i;

	for (i = 0; i < WG_KEY_LEN / 3; ++i)
		encode_base64(&base64[i * 4], &key[i * 3]);
	encode_base64(&base64[i * 4], (const uint8_t[]){ key[i * 3 + 0], key[i * 3 + 1], 0 });
	base64[WG_KEY_LEN_BASE64 - 2] = '=';
	base64[WG_KEY_LEN_BASE64 - 1] = '\0';
}

static char *key(const uint8_t key[static WG_KEY_LEN])
{
	static char base64[WG_KEY_LEN_BASE64];

	key_to_base64(base64, key);
	return base64;
}

static char *endpoint(const struct sockaddr *addr)
{
	char host[4096 + 1];
	char service[512 + 1];
	static char buf[sizeof(host) + sizeof(service) + 4];
	int ret;
	socklen_t addr_len = 0;

	memset(buf, 0, sizeof(buf));
	if (addr->sa_family == AF_INET)
		addr_len = sizeof(struct sockaddr_in);
	else if (addr->sa_family == AF_INET6)
		addr_len = sizeof(struct sockaddr_in6);

	ret = getnameinfo(addr, addr_len, host, sizeof(host), service, sizeof(service), NI_DGRAM | NI_NUMERICSERV | NI_NUMERICHOST);
	if (ret) {
		strncpy(buf, gai_strerror(ret), sizeof(buf) - 1);
		buf[sizeof(buf) - 1] = '\0';
	} else
		snprintf(buf, sizeof(buf), (addr->sa_family == AF_INET6 && strchr(host, ':')) ? "[%s]:%s" : "%s:%s", host, service);
	return buf;
}

static int get_ifname(struct nlattr *tb[], char **ifname)
{
	if (tb[WGDEVICE_A_IFNAME] == NULL)
		return -1;
	*ifname = nla_data(tb[WGDEVICE_A_IFNAME]);
	return 0;
}

static int get_pubkey(struct nlattr *peer[], char **pubkey)
{
	if (peer[WGPEER_A_PUBLIC_KEY] == NULL)
		return -1;
	*pubkey = key(nla_data(peer[WGPEER_A_PUBLIC_KEY]));
	return 0;
}

static int get_endpoint(struct nlattr *peer[], char **endpoint_ip)
{
	if (peer[WGPEER_A_ENDPOINT] == NULL)
		return -1;
	*endpoint_ip = endpoint(nla_data(peer[WGPEER_A_ENDPOINT]));
	return 0;
}

static int run_callback(char *ifname, char *pubkey, char *endpoint_ip, bool advanced_security)
{
	char** new_argv = malloc((cb_argc + 2) * sizeof *new_argv);

	new_argv[0] = cb_argv[1];
	for (int i = 2; i < cb_argc - 3; i++) {
		new_argv[i - 1] = cb_argv[i];
	}
	new_argv[cb_argc - 4] = ifname;
	new_argv[cb_argc - 3] = pubkey;
	new_argv[cb_argc - 2] = endpoint_ip;
	new_argv[cb_argc - 1] = (advanced_security ? "on\0" : "off\0");
	new_argv[cb_argc] = NULL;

	int child_pid = fork(), ret;
	if (child_pid < 0) {
		prerr("failed to spawn child process: %d\n", child_pid);
		return child_pid;
	} else if (child_pid == 0) {
		execv(cb_argv[1], new_argv);
		exit(0);
	} else {
		waitpid(child_pid, &ret, 0);
	}

	free(new_argv);
	return ret;
}

static int netlink_callback(struct nl_msg *msg, void *arg)
{
	struct nlmsghdr *ret_hdr = nlmsg_hdr(msg);
	struct genlmsghdr *gnlh = nlmsg_data(ret_hdr);
	struct nlattr *tb[WGDEVICE_A_MAX + 1];
	struct nlattr *peer[WGPEER_A_MAX + 1];

	nla_parse(tb, WGDEVICE_A_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL);

	char *ifname, *pubkey, *endpoint_ip;
	bool advanced_security = false;
	int cb_ret;

	switch (gnlh->cmd) {
		case WG_CMD_UNKNOWN_PEER:
			if (get_ifname(tb, &ifname) < 0) {
				prerr("unknown interface name!\n");
				return NL_SKIP;
			}
			if (nla_parse_nested(peer, WGPEER_A_MAX, tb[WGDEVICE_A_PEER], NULL)) {
				prerr("failed to parse nested peer!\n");
				return NL_SKIP;
			}
			if (get_pubkey(peer, &pubkey)) {
				prerr("invalid public key!\n");
				return NL_SKIP;
			}
			if (get_endpoint(peer, &endpoint_ip)) {
				prerr("invalid endpoint!\n");
				return NL_SKIP;
			}
			if (nla_get_flag(peer[WGPEER_A_ADVANCED_SECURITY])) {
				advanced_security = true;
			}
			if (cb_ret = run_callback(ifname, pubkey, endpoint_ip, advanced_security)) {
				prerr("failed to execute callback script: %d!\n", cb_ret);
				return NL_SKIP;
			}
			printf("Callback executed successfully.\n");
			break;
		default:
			return NL_SKIP;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	int    ret;
	int    sk_fd;
	fd_set rfds;

	if (argc < 2) {
		prerr("usage: %s <callback>\n", argv[0]);
		cleanup_and_exit(EXIT_FAILURE);
	}

	cb_argc = argc + 3;
	cb_argv = argv;

	signal(SIGTERM, signal_handler);
	signal(SIGINT, signal_handler);

	sk = nl_socket_alloc();
	if (sk == NULL) {
		prerr("unable to allocate Netlink socket!\n");
		exit(EXIT_FAILURE);
	}

	ret = genl_connect(sk);
	if (ret < 0) {
		prerr("no connect %d!\n", ret);
		cleanup_and_exit(EXIT_FAILURE);
	}

	printf("Netlink socket connected.\n");

	ret = genl_ctrl_resolve_grp(sk, WG_GENL_NAME, WG_MULTICAST_GROUP_AUTH);
	if (ret < 0) {
		prerr("auth group not found %d!\n", ret);
		cleanup_and_exit(EXIT_FAILURE);
	}

	ret = nl_socket_add_membership(sk, ret);
	if (ret < 0) {
		prerr("unable to join multicast group %d!\n", ret);
		cleanup_and_exit(EXIT_FAILURE);
	}

	nl_socket_disable_seq_check(sk);
	ret = nl_socket_modify_cb(sk, NL_CB_VALID, NL_CB_CUSTOM, netlink_callback, NULL);
	if (ret < 0) {
		prerr("unable to register callback %d!\n", ret);
		cleanup_and_exit(EXIT_FAILURE);
	}

	while (1) {
		FD_ZERO(&rfds);

		sk_fd = nl_socket_get_fd(sk);
		FD_SET(sk_fd, &rfds);

		ret = select(sk_fd + 1, &rfds, NULL, NULL, NULL);
		if (ret < 0)
			break;

		ret = nl_recvmsgs_default(sk);
		if (ret < 0) {
			prerr("error receiving message %d!\n", ret);
			cleanup_and_exit(EXIT_FAILURE);
		}
	}

	cleanup_and_exit(EXIT_FAILURE);
}