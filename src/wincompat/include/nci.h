/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2018-2021 WireGuard LLC. All Rights Reserved.
 */

#ifndef _NCI_H
#define _NCI_H

#include <windows.h>

#ifdef GENERATE_LIB
#define DECLSPEC __declspec(dllexport)
#define STUB { return 0; }
#else
#define DECLSPEC __declspec(dllimport)
#define STUB ;
#endif


EXTERN_C DECLSPEC DWORD WINAPI
NciSetConnectionName(const GUID *Guid, const WCHAR *NewName) STUB

EXTERN_C DECLSPEC DWORD WINAPI
NciGetConnectionName(
    const GUID *Guid,
    WCHAR *Name,
    DWORD InDestNameBytes,
    DWORD *OutDestNameBytes) STUB

#endif
