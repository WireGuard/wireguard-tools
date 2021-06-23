/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2021 WireGuard LLC. All Rights Reserved.
 */

#ifndef _WIREGUARD_NT_H
#define _WIREGUARD_NT_H

#include <ntdef.h>
#include <ws2def.h>
#include <ws2ipdef.h>
#include <inaddr.h>
#include <in6addr.h>

#define WG_KEY_LEN 32
#define WG_MAX_LOG_LINE_LEN 128

typedef struct _WG_IOCTL_ALLOWED_IP
{
    union
    {
	IN_ADDR V4;
	IN6_ADDR V6;
    } Address;
    ADDRESS_FAMILY AddressFamily;
    UCHAR Cidr;
} __attribute__((aligned(8))) WG_IOCTL_ALLOWED_IP;

typedef enum
{
    WG_IOCTL_PEER_HAS_PUBLIC_KEY = 1 << 0,
    WG_IOCTL_PEER_HAS_PRESHARED_KEY = 1 << 1,
    WG_IOCTL_PEER_HAS_PERSISTENT_KEEPALIVE = 1 << 2,
    WG_IOCTL_PEER_HAS_ENDPOINT = 1 << 3,
    WG_IOCTL_PEER_HAS_PROTOCOL_VERSION = 1 << 4,
    WG_IOCTL_PEER_REPLACE_ALLOWED_IPS = 1 << 5,
    WG_IOCTL_PEER_REMOVE = 1 << 6,
    WG_IOCTL_PEER_UPDATE = 1 << 7
} WG_IOCTL_PEER_FLAG;

typedef struct _WG_IOCTL_PEER
{
    WG_IOCTL_PEER_FLAG Flags;
    ULONG ProtocolVersion; /* 0 = latest protocol, 1 = this protocol. */
    UCHAR PublicKey[WG_KEY_LEN];
    UCHAR PresharedKey[WG_KEY_LEN];
    USHORT PersistentKeepalive;
    SOCKADDR_INET Endpoint;
    ULONG64 TxBytes;
    ULONG64 RxBytes;
    ULONG64 LastHandshake;
    ULONG AllowedIPsCount;
} __attribute__((aligned(8))) WG_IOCTL_PEER;

typedef enum
{
    WG_IOCTL_INTERFACE_HAS_PUBLIC_KEY = 1 << 0,
    WG_IOCTL_INTERFACE_HAS_PRIVATE_KEY = 1 << 1,
    WG_IOCTL_INTERFACE_HAS_LISTEN_PORT = 1 << 2,
    WG_IOCTL_INTERFACE_REPLACE_PEERS = 1 << 3
} WG_IOCTL_INTERFACE_FLAG;

typedef struct _WG_IOCTL_INTERFACE
{
    WG_IOCTL_INTERFACE_FLAG Flags;
    USHORT ListenPort;
    UCHAR PrivateKey[WG_KEY_LEN];
    UCHAR PublicKey[WG_KEY_LEN];
    ULONG PeersCount;
} __attribute__((aligned(8))) WG_IOCTL_INTERFACE;

/* Get adapter properties.
 *
 * The lpOutBuffer and nOutBufferSize parameters of DeviceIoControl() must describe an user allocated buffer
 * and its size in bytes. The buffer will be filled with a WG_IOCTL_INTERFACE struct followed by zero or more
 * WG_IOCTL_PEER structs. Should all data not fit into the buffer, ERROR_MORE_DATA is returned with the required
 * size of the buffer.
 */
#define WG_IOCTL_GET CTL_CODE(51821U, 0xc71U, METHOD_OUT_DIRECT, FILE_READ_DATA | FILE_WRITE_DATA)

/* Set adapter properties.
 *
 * The lpInBuffer and nInBufferSize parameters of DeviceIoControl() must describe a WG_IOCTL_INTERFACE struct followed
 * by PeersCount times WG_IOCTL_PEER struct.
 */
#define WG_IOCTL_SET CTL_CODE(51821U, 0xc70U, METHOD_IN_DIRECT, FILE_READ_DATA | FILE_WRITE_DATA)

/* Bring adapter up. */
#define WG_IOCTL_UP CTL_CODE(51821U, 0x9f4U, METHOD_NEITHER, FILE_READ_DATA | FILE_WRITE_DATA)

/* Bring adapter down. */
#define WG_IOCTL_DOWN CTL_CODE(51821U, 0x9f5U, METHOD_NEITHER, FILE_READ_DATA | FILE_WRITE_DATA)

/* Read the next line in the adapter log. */
#define WG_IOCTL_READ_LOG_LINE CTL_CODE(51821U, 0xa01U, METHOD_OUT_DIRECT, FILE_READ_DATA | FILE_WRITE_DATA)

/* Force close all open handles to allow for driver removal. */
#define WG_IOCTL_FORCE_CLOSE_HANDLES CTL_CODE(51821U, 0xa71U, METHOD_NEITHER, FILE_READ_DATA | FILE_WRITE_DATA)

#endif
