// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2015-2021 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#include "containers.h"
#include <windows.h>
#include <setupapi.h>
#include <cfgmgr32.h>
#include <iphlpapi.h>
#include <initguid.h>
#include <devguid.h>
#include <ddk/ndisguid.h>
#include <nci.h>
#include <wireguard.h>

#define IPC_SUPPORTS_KERNEL_INTERFACE

static int kernel_get_wireguard_interfaces(struct string_list *list)
{
	HDEVINFO dev_info = SetupDiGetClassDevsExW(&GUID_DEVCLASS_NET, NULL, NULL, DIGCF_PRESENT, NULL, NULL, NULL);

	if (dev_info == INVALID_HANDLE_VALUE) {
		errno = EACCES;
		return -errno;
	}

	for (DWORD i = 0;; ++i) {
		bool found = false;
		DWORD buf_len = 0, value_type, ret;
		WCHAR *buf = NULL, adapter_name[MAX_ADAPTER_NAME];
		SP_DEVINFO_DATA dev_info_data = { .cbSize = sizeof(SP_DEVINFO_DATA) };
		HKEY key;
		GUID instance_id;
		char *interface_name;

		if (!SetupDiEnumDeviceInfo(dev_info, i, &dev_info_data)) {
			if (GetLastError() == ERROR_NO_MORE_ITEMS)
				break;
			continue;
		}

		while (!SetupDiGetDeviceRegistryPropertyW(dev_info, &dev_info_data, SPDRP_HARDWAREID, &value_type, (BYTE *)buf, buf_len, &buf_len)) {
			free(buf);
			if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
				goto skip;
			buf = malloc(buf_len);
			if (!buf)
				goto skip;
		}

		if (!buf || value_type != REG_MULTI_SZ || buf_len < sizeof(*buf) * 2 || buf[buf_len / sizeof(*buf) - 1] || buf[buf_len / sizeof(*buf) - 2]) {
			free(buf);
			continue;
		}

		for (WCHAR *item = buf; *item; item += wcslen(item) + 1) {
			if (!_wcsicmp(item, L"wireguard")) {
				found = true;
				break;
			}
		}
		free(buf);
		if (!found)
			continue;
		buf = NULL;
		buf_len = 0;

		key = SetupDiOpenDevRegKey(dev_info, &dev_info_data, DICS_FLAG_GLOBAL, 0, DIREG_DRV, KEY_QUERY_VALUE);
		if (key == INVALID_HANDLE_VALUE)
			continue;
		buf_len = 39 * sizeof(*buf);
		buf = malloc(buf_len);
		if (!buf)
			continue;
		while ((ret = RegQueryValueExW(key, L"NetCfgInstanceId", NULL, &value_type, (BYTE *)buf, &buf_len)) != ERROR_SUCCESS) {
			free(buf);
			if (ret != ERROR_MORE_DATA)
				goto cleanup_key;
			buf = malloc(buf_len);
			if (!buf)
				goto cleanup_key;
		}
		if (!buf || value_type != REG_SZ || buf_len < sizeof(*buf) || buf[buf_len / sizeof(*buf) - 1])
			goto cleanup_buf;
		if (FAILED(CLSIDFromString(buf, &instance_id)))
			goto cleanup_buf;

		if (NciGetConnectionName(&instance_id, adapter_name, sizeof(adapter_name), NULL) != ERROR_SUCCESS)
			goto cleanup_buf;
		adapter_name[_countof(adapter_name) - 1] = L'0';
		if (!adapter_name[0])
			goto cleanup_buf;

		buf_len = WideCharToMultiByte(CP_UTF8, 0, adapter_name, -1, NULL, 0, NULL, NULL);
		if (!buf_len)
			goto cleanup_buf;
		interface_name = malloc(buf_len);
		if (!interface_name)
			goto cleanup_buf;
		buf_len = WideCharToMultiByte(CP_UTF8, 0, adapter_name, -1, interface_name, buf_len, NULL, NULL);
		if (!buf_len) {
			free(interface_name);
			goto cleanup_buf;
		}

		string_list_add(list, interface_name);
		free(interface_name);
cleanup_buf:
		free(buf);
cleanup_key:
		RegCloseKey(key);
skip:;
	}
	SetupDiDestroyDeviceInfoList(dev_info);
	return 0;
}

static HANDLE kernel_interface_handle(const char *iface)
{
	HDEVINFO dev_info = SetupDiGetClassDevsExW(&GUID_DEVCLASS_NET, NULL, NULL, DIGCF_PRESENT, NULL, NULL, NULL);
	WCHAR *interfaces = NULL;
	HANDLE handle;

	if (dev_info == INVALID_HANDLE_VALUE)
		return NULL;

	for (DWORD i = 0; !interfaces; ++i) {
		bool found = false;
		DWORD buf_len = 0, value_type, ret;
		WCHAR *buf = NULL, adapter_name[MAX_ADAPTER_NAME];
		SP_DEVINFO_DATA dev_info_data = { .cbSize = sizeof(SP_DEVINFO_DATA) };
		HKEY key;
		GUID instance_id;
		char *interface_name;

		if (!SetupDiEnumDeviceInfo(dev_info, i, &dev_info_data)) {
			if (GetLastError() == ERROR_NO_MORE_ITEMS)
				break;
			continue;
		}

		while (!SetupDiGetDeviceRegistryPropertyW(dev_info, &dev_info_data, SPDRP_HARDWAREID, &value_type, (BYTE *)buf, buf_len, &buf_len)) {
			free(buf);
			if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
				goto skip;
			buf = malloc(buf_len);
			if (!buf)
				goto skip;
		}

		if (!buf || value_type != REG_MULTI_SZ || buf_len < sizeof(*buf) * 2 || buf[buf_len / sizeof(*buf) - 1] || buf[buf_len / sizeof(*buf) - 2]) {
			free(buf);
			continue;
		}

		for (WCHAR *item = buf; *item; item += wcslen(item) + 1) {
			if (!_wcsicmp(item, L"wireguard")) {
				found = true;
				break;
			}
		}
		free(buf);
		if (!found)
			continue;
		found = false;
		buf = NULL;
		buf_len = 0;

		key = SetupDiOpenDevRegKey(dev_info, &dev_info_data, DICS_FLAG_GLOBAL, 0, DIREG_DRV, KEY_QUERY_VALUE);
		if (key == INVALID_HANDLE_VALUE)
			continue;
		buf_len = 39 * sizeof(*buf);
		buf = malloc(buf_len);
		if (!buf)
			continue;
		while ((ret = RegQueryValueExW(key, L"NetCfgInstanceId", NULL, &value_type, (BYTE *)buf, &buf_len)) != ERROR_SUCCESS) {
			free(buf);
			if (ret != ERROR_MORE_DATA)
				goto cleanup_key;
			buf = malloc(buf_len);
			if (!buf)
				goto cleanup_key;
		}
		if (!buf || value_type != REG_SZ || buf_len < sizeof(*buf) || buf[buf_len / sizeof(*buf) - 1])
			goto cleanup_buf;
		if (FAILED(CLSIDFromString(buf, &instance_id)))
			goto cleanup_buf;

		if (NciGetConnectionName(&instance_id, adapter_name, sizeof(adapter_name), NULL) != ERROR_SUCCESS)
			goto cleanup_buf;
		adapter_name[_countof(adapter_name) - 1] = L'0';
		if (!adapter_name[0])
			goto cleanup_buf;

		buf_len = WideCharToMultiByte(CP_UTF8, 0, adapter_name, -1, NULL, 0, NULL, NULL);
		if (!buf_len)
			goto cleanup_buf;
		interface_name = malloc(buf_len);
		if (!interface_name)
			goto cleanup_buf;
		buf_len = WideCharToMultiByte(CP_UTF8, 0, adapter_name, -1, interface_name, buf_len, NULL, NULL);
		if (!buf_len) {
			free(interface_name);
			goto cleanup_buf;
		}
		found = !strcmp(interface_name, iface);
		free(interface_name);
cleanup_buf:
		free(buf);
cleanup_key:
		RegCloseKey(key);
		if (!found)
			continue;

		if (SetupDiGetDeviceInstanceIdW(dev_info, &dev_info_data, NULL, 0, &buf_len) || GetLastError() != ERROR_INSUFFICIENT_BUFFER)
			continue;
		buf = calloc(sizeof(*buf), buf_len);
		if (!buf)
			continue;
		if (!SetupDiGetDeviceInstanceIdW(dev_info, &dev_info_data, buf, buf_len, &buf_len))
			goto cleanup_instance_id;
		if (CM_Get_Device_Interface_List_SizeW(
			&buf_len, (GUID *)&GUID_DEVINTERFACE_NET, (DEVINSTID_W)buf,
			CM_GET_DEVICE_INTERFACE_LIST_PRESENT) != CR_SUCCESS)
			goto cleanup_instance_id;
		interfaces = calloc(buf_len, sizeof(*interfaces));
		if (!interfaces)
			goto cleanup_instance_id;
		if (CM_Get_Device_Interface_ListW(
			(GUID *)&GUID_DEVINTERFACE_NET, (DEVINSTID_W)buf, interfaces, buf_len,
			CM_GET_DEVICE_INTERFACE_LIST_PRESENT) != CR_SUCCESS || !interfaces[0]) {
			free(interfaces);
			interfaces = NULL;
			goto cleanup_instance_id;
		}
cleanup_instance_id:
		free(buf);
skip:;
	}
	SetupDiDestroyDeviceInfoList(dev_info);
	if (!interfaces) {
		errno = ENOENT;
		return NULL;
	}
	handle = CreateFileW(interfaces, GENERIC_READ | GENERIC_WRITE,
			     FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
			     OPEN_EXISTING, 0, NULL);
	free(interfaces);
	if (handle == INVALID_HANDLE_VALUE) {
		errno = EACCES;
		return NULL;
	}
	return handle;
}

static BOOL elevated_ioctl(HANDLE handle, DWORD code, void *in_buf, DWORD in_buf_len, void *out_buf, DWORD out_buf_len, DWORD *bytes_returned)
{
	HANDLE thread_token, process_snapshot, winlogon_process, winlogon_token, duplicated_token;
	PROCESSENTRY32 entry = { .dwSize = sizeof(PROCESSENTRY32) };
	TOKEN_PRIVILEGES privileges = {
		.PrivilegeCount = 1,
		.Privileges = {{ .Attributes = SE_PRIVILEGE_ENABLED }}
	};
	SID expected_sid;
	DWORD bytes = sizeof(expected_sid);
	BOOL ret;

	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &privileges.Privileges[0].Luid))
		return FALSE;
	if (!CreateWellKnownSid(WinLocalSystemSid, NULL, &expected_sid, &bytes))
		return FALSE;

	process_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (process_snapshot == INVALID_HANDLE_VALUE)
		return FALSE;
	for (ret = Process32First(process_snapshot, &entry); ret; ret = Process32Next(process_snapshot, &entry)) {
		if (strcasecmp(entry.szExeFile, "winlogon.exe"))
			continue;

		RevertToSelf();
		if (!ImpersonateSelf(SecurityImpersonation))
			continue;
		if (!OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES, FALSE, &thread_token))
			continue;
		if (!AdjustTokenPrivileges(thread_token, FALSE, &privileges, sizeof(privileges), NULL, NULL)) {
			CloseHandle(thread_token);
			continue;
		}
		CloseHandle(thread_token);

		winlogon_process = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, entry.th32ProcessID);
		if (!winlogon_process)
			continue;
		if (!OpenProcessToken(winlogon_process, TOKEN_IMPERSONATE | TOKEN_DUPLICATE, &winlogon_token))
			continue;
		CloseHandle(winlogon_process);
		if (!DuplicateToken(winlogon_token, SecurityImpersonation, &duplicated_token)) {
			RevertToSelf();
			continue;
		}
		CloseHandle(winlogon_token);
		if (!SetThreadToken(NULL, duplicated_token)) {
			CloseHandle(duplicated_token);
			continue;
		}
		CloseHandle(duplicated_token);
		ret = DeviceIoControl(handle, code, in_buf, in_buf_len, out_buf, out_buf_len, bytes_returned, NULL);
		break;
	}

	RevertToSelf();
	CloseHandle(process_snapshot);
	return ret;
}

static int kernel_get_device(struct wgdevice **device, const char *iface)
{
	WG_IOCTL_INTERFACE *wg_iface;
	WG_IOCTL_PEER *wg_peer;
	WG_IOCTL_ALLOWED_IP *wg_aip;
	void *buf = NULL;
	DWORD buf_len = 0;
	HANDLE handle = kernel_interface_handle(iface);
	struct wgdevice *dev;
	struct wgpeer *peer;
	struct wgallowedip *aip;
	int ret;

	*device = NULL;

	if (!handle)
		return -errno;

	while (!elevated_ioctl(handle, WG_IOCTL_GET, NULL, 0, buf, buf_len, &buf_len)) {
		free(buf);
		if (GetLastError() != ERROR_MORE_DATA) {
			errno = EIO;
			return -errno;
		}
		buf = malloc(buf_len);
		if (!buf)
			return -errno;
	}

	wg_iface = (WG_IOCTL_INTERFACE *)buf;
	dev = calloc(1, sizeof(*dev));
	if (!dev)
		goto out;
	strncpy(dev->name, iface, sizeof(dev->name));
	dev->name[sizeof(dev->name) - 1] = '\0';

	if (wg_iface->Flags & WG_IOCTL_INTERFACE_HAS_LISTEN_PORT) {
		dev->listen_port = wg_iface->ListenPort;
		dev->flags |= WGDEVICE_HAS_LISTEN_PORT;
	}

	if (wg_iface->Flags & WG_IOCTL_INTERFACE_HAS_PUBLIC_KEY) {
		memcpy(dev->public_key, wg_iface->PublicKey, sizeof(dev->public_key));
		dev->flags |= WGDEVICE_HAS_PUBLIC_KEY;
	}

	if (wg_iface->Flags & WG_IOCTL_INTERFACE_HAS_PRIVATE_KEY) {
		memcpy(dev->private_key, wg_iface->PrivateKey, sizeof(dev->private_key));
		dev->flags |= WGDEVICE_HAS_PRIVATE_KEY;
	}

	wg_peer = buf + sizeof(WG_IOCTL_INTERFACE);
	for (ULONG i = 0; i < wg_iface->PeersCount; ++i) {
		peer = calloc(1, sizeof(*peer));
		if (!peer)
			goto out;

		if (dev->first_peer == NULL)
			dev->first_peer = peer;
		else
			dev->last_peer->next_peer = peer;
		dev->last_peer = peer;

		if (wg_peer->Flags & WG_IOCTL_PEER_HAS_PUBLIC_KEY) {
			memcpy(peer->public_key, wg_peer->PublicKey, sizeof(peer->public_key));
			peer->flags |= WGPEER_HAS_PUBLIC_KEY;
		}

		if (wg_peer->Flags & WG_IOCTL_PEER_HAS_PRESHARED_KEY) {
			memcpy(peer->preshared_key, wg_peer->PresharedKey, sizeof(peer->preshared_key));
			if (!key_is_zero(peer->preshared_key))
				peer->flags |= WGPEER_HAS_PRESHARED_KEY;
		}

		if (wg_peer->Flags & WG_IOCTL_PEER_HAS_PERSISTENT_KEEPALIVE) {
			peer->persistent_keepalive_interval = wg_peer->PersistentKeepalive;
			peer->flags |= WGPEER_HAS_PERSISTENT_KEEPALIVE_INTERVAL;
		}

		if (wg_peer->Flags & WG_IOCTL_PEER_HAS_ENDPOINT) {
			if (wg_peer->Endpoint.si_family == AF_INET)
				peer->endpoint.addr4 = wg_peer->Endpoint.Ipv4;
			else if (wg_peer->Endpoint.si_family == AF_INET6)
				peer->endpoint.addr6 = wg_peer->Endpoint.Ipv6;
		}

		peer->rx_bytes = wg_peer->RxBytes;
		peer->tx_bytes = wg_peer->TxBytes;

		if (wg_peer->LastHandshake) {
			peer->last_handshake_time.tv_sec = wg_peer->LastHandshake / 10000000 - 11644473600LL;
			peer->last_handshake_time.tv_nsec = wg_peer->LastHandshake % 10000000 * 100;
		}

		wg_aip = (void *)wg_peer + sizeof(WG_IOCTL_PEER);
		for (ULONG j = 0; j < wg_peer->AllowedIPsCount; ++j) {
			aip = calloc(1, sizeof(*aip));
			if (!aip)
				goto out;

			if (peer->first_allowedip == NULL)
				peer->first_allowedip = aip;
			else
				peer->last_allowedip->next_allowedip = aip;
			peer->last_allowedip = aip;

			aip->family = wg_aip->AddressFamily;
			if (wg_aip->AddressFamily == AF_INET) {
				memcpy(&aip->ip4, &wg_aip->Address.V4, sizeof(aip->ip4));
				aip->cidr = wg_aip->Cidr;
			} else if (wg_aip->AddressFamily == AF_INET6) {
				memcpy(&aip->ip6, &wg_aip->Address.V6, sizeof(aip->ip6));
				aip->cidr = wg_aip->Cidr;
			}
			++wg_aip;
		}
		wg_peer = (WG_IOCTL_PEER *)wg_aip;
	}
	*device = dev;
	errno = 0;
out:
	ret = -errno;
	free(buf);
	CloseHandle(handle);
	return ret;
}

static int kernel_set_device(struct wgdevice *dev)
{
	WG_IOCTL_INTERFACE *wg_iface;
	WG_IOCTL_PEER *wg_peer;
	WG_IOCTL_ALLOWED_IP *wg_aip;
	size_t buf_len = sizeof(WG_IOCTL_INTERFACE);
	HANDLE handle = kernel_interface_handle(dev->name);
	struct wgpeer *peer;
	struct wgallowedip *aip;
	size_t peer_count, aip_count;
	int ret = 0;

	if (!handle)
		return -errno;

	for_each_wgpeer(dev, peer) {
		buf_len += sizeof(WG_IOCTL_PEER);
		for_each_wgallowedip(peer, aip)
			buf_len += sizeof(WG_IOCTL_ALLOWED_IP);
	}
	wg_iface = calloc(1, buf_len);
	if (!wg_iface)
		return -errno;

	if (dev->flags & WGDEVICE_HAS_PRIVATE_KEY) {
		memcpy(wg_iface->PrivateKey, dev->private_key, sizeof(wg_iface->PrivateKey));
		wg_iface->Flags |= WG_IOCTL_INTERFACE_HAS_PRIVATE_KEY;
	}

	if (dev->flags & WGDEVICE_HAS_LISTEN_PORT) {
		wg_iface->ListenPort = dev->listen_port;
		wg_iface->Flags |= WG_IOCTL_INTERFACE_HAS_LISTEN_PORT;
	}

	if (dev->flags & WGDEVICE_REPLACE_PEERS)
		wg_iface->Flags |= WG_IOCTL_INTERFACE_REPLACE_PEERS;

	peer_count = 0;
	wg_peer = (void *)wg_iface + sizeof(WG_IOCTL_INTERFACE);
	for_each_wgpeer(dev, peer) {
		wg_peer->Flags = WG_IOCTL_PEER_HAS_PUBLIC_KEY;
		memcpy(wg_peer->PublicKey, peer->public_key, sizeof(wg_peer->PublicKey));

		if (peer->flags & WGPEER_HAS_PRESHARED_KEY) {
			memcpy(wg_peer->PresharedKey, peer->preshared_key, sizeof(wg_peer->PresharedKey));
			wg_peer->Flags |= WG_IOCTL_PEER_HAS_PRESHARED_KEY;
		}

		if (peer->flags & WGPEER_HAS_PERSISTENT_KEEPALIVE_INTERVAL) {
			wg_peer->PersistentKeepalive = peer->persistent_keepalive_interval;
			wg_peer->Flags |= WG_IOCTL_PEER_HAS_PERSISTENT_KEEPALIVE;
		}

		if (peer->endpoint.addr.sa_family == AF_INET) {
			wg_peer->Endpoint.Ipv4 = peer->endpoint.addr4;
			wg_peer->Flags |= WG_IOCTL_PEER_HAS_ENDPOINT;
		} else if (peer->endpoint.addr.sa_family == AF_INET6) {
			wg_peer->Endpoint.Ipv6 = peer->endpoint.addr6;
			wg_peer->Flags |= WG_IOCTL_PEER_HAS_ENDPOINT;
		}

		if (peer->flags & WGPEER_REPLACE_ALLOWEDIPS)
			wg_peer->Flags |= WG_IOCTL_PEER_REPLACE_ALLOWED_IPS;

		if (peer->flags & WGPEER_REMOVE_ME)
			wg_peer->Flags |= WG_IOCTL_PEER_REMOVE;

		aip_count = 0;
		wg_aip = (void *)wg_peer + sizeof(WG_IOCTL_PEER);
		for_each_wgallowedip(peer, aip) {
			wg_aip->AddressFamily = aip->family;
			wg_aip->Cidr = aip->cidr;

			if (aip->family == AF_INET)
				wg_aip->Address.V4 = aip->ip4;
			else if (aip->family == AF_INET6)
				wg_aip->Address.V6 = aip->ip6;
			else
				continue;
			++aip_count;
			++wg_aip;
		}
		wg_peer->AllowedIPsCount = aip_count;
		++peer_count;
		wg_peer = (WG_IOCTL_PEER *)wg_aip;
	}
	wg_iface->PeersCount = peer_count;

	if (!elevated_ioctl(handle, WG_IOCTL_SET, NULL, 0, wg_iface, buf_len, &buf_len))
		goto out;
	errno = 0;

out:
	ret = -errno;
	free(wg_iface);
	CloseHandle(handle);
	return ret;
}
