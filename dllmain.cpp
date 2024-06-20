#include <bit>
#include "Plugin_SDK.h"
#include "xxh_x86dispatch.h"

BOOL WINAPI DllMain(HINSTANCE hinstDll, DWORD dwReason, LPVOID lpReserved) {
    return TRUE;
}

BOOL HSPCALL HSP_Initialize(CPHSP_InitInfo cpInitInfo, PHSP_PluginBasicInfo pPluginBasicInfo) {
    static const GUID pluginGuid{
        0xc51b890c, 0xc649, 0x4958, { 0x8c, 0x7c, 0x55, 0xe5, 0x15, 0x7b, 0x37, 0xb6 }
    };
    pPluginBasicInfo->eHSPFuncFlags = HSPFuncFlags_Hash;
    pPluginBasicInfo->pGuid = &pluginGuid;
    pPluginBasicInfo->pluginInterfaceVer = HSP_INTERFACE_VER;
    pPluginBasicInfo->pluginSDKVer = HSP_SDK_VER;
    return TRUE;
}

LRESULT HSPCALL HSP_PluginFunc(HSPPFMsg uMsg, WPARAM wParam, LPARAM lParam) {
    if (uMsg == HSPPFMsg_Hash_GetSupportAlgCount) return 4;

    auto AlgID = (uint32_t)lParam;

    if (AlgID == 0) {
        static const char16_t* hashName = (const char16_t*)L"xxHash-32";

        static const GUID hashGuid{
            0x877ed0bb, 0xfb15, 0x4818, { 0x29, 0xf0, 0xdb, 0x8f, 0x71, 0x60, 0x91, 0x06 }
        };

        if (uMsg == HSPPFMsg_Hash_GetAlgInfo) {
            auto pAlgInfo = (PHSP_AlgInfo)wParam;
            pAlgInfo->BlockSizeOctets = 0;
            pAlgInfo->DigestSize = 4;
            pAlgInfo->szAlgName = hashName;
            return TRUE;
        }

        if (uMsg == HSPPFMsg_Hash_GetAlgInfoEx) {
            auto pAlgInfoEx = (PHSP_AlgInfoEx)wParam;
            pAlgInfoEx->eHSPAlgFlags = HSPAlgFlags_None;
            pAlgInfoEx->pGuid = &hashGuid;
            pAlgInfoEx->szAlgFileName = hashName;
            return TRUE;
        }

        if (uMsg == HSPPFMsg_Hash_GetAlgFunctions) {
            auto pAlgFunctions = (PHSP_AlgFunctions)wParam;
            pAlgFunctions->fpHSP_HashInitialize = [](uint32_t AlgID) -> void* {
                auto state = XXH32_createState();
                XXH32_reset(state, 0);
                return state;
            };
            pAlgFunctions->fpHSP_HashUpdate = [](void* state, const uint8_t* data, rsize_t dataOctets) {
                XXH32_update((XXH32_state_t*)state, data, dataOctets);
            };
            pAlgFunctions->fpHSP_HashGetHex = [](void* state, uint8_t* digest, rsize_t getOctets) {
                auto hash = XXH32_digest((XXH32_state_t*)state);
                hash = std::byteswap(hash);
                memcpy_s(digest, getOctets, &hash, sizeof(hash));
            };
            pAlgFunctions->fpHSP_HashReset = [](void* state) {
                XXH32_reset((XXH32_state_t*)state, 0);
            };
            pAlgFunctions->fpHSP_HashFinalize = [](void* state) {
                XXH32_freeState((XXH32_state_t*)state);
            };
            pAlgFunctions->fpHSP_HashClone = [](void* state) -> void* {
                auto clone = XXH32_createState();
                XXH32_copyState(clone, (XXH32_state_t*)state);
                return clone;
            };
            return TRUE;
        }
    }

    if (AlgID == 1) {
        static const char16_t* hashName = (const char16_t*)L"xxHash-64";

        static const GUID hashGuid{
            0x566fed6c, 0x6c7e, 0x4d04, { 0x5f, 0xa5, 0x20, 0xbd, 0x79, 0x23, 0x58, 0xf9 }
        };

        if (uMsg == HSPPFMsg_Hash_GetAlgInfo) {
            auto pAlgInfo = (PHSP_AlgInfo)wParam;
            pAlgInfo->BlockSizeOctets = 0;
            pAlgInfo->DigestSize = 8;
            pAlgInfo->szAlgName = hashName;
            return TRUE;
        }

        if (uMsg == HSPPFMsg_Hash_GetAlgInfoEx) {
            auto pAlgInfoEx = (PHSP_AlgInfoEx)wParam;
            pAlgInfoEx->eHSPAlgFlags = HSPAlgFlags_None;
            pAlgInfoEx->pGuid = &hashGuid;
            pAlgInfoEx->szAlgFileName = hashName;
            return TRUE;
        }

        if (uMsg == HSPPFMsg_Hash_GetAlgFunctions) {
            auto pAlgFunctions = (PHSP_AlgFunctions)wParam;
            pAlgFunctions->fpHSP_HashInitialize = [](uint32_t AlgID) -> void* {
                auto state = XXH64_createState();
                XXH64_reset(state, 0);
                return state;
            };
            pAlgFunctions->fpHSP_HashUpdate = [](void* state, const uint8_t* data, rsize_t dataOctets) {
                XXH64_update((XXH64_state_t*)state, data, dataOctets);
            };
            pAlgFunctions->fpHSP_HashGetHex = [](void* state, uint8_t* digest, rsize_t getOctets) {
                auto hash = XXH64_digest((XXH64_state_t*)state);
                hash = std::byteswap(hash);
                memcpy_s(digest, getOctets, &hash, sizeof(hash));
            };
            pAlgFunctions->fpHSP_HashReset = [](void* state) {
                XXH64_reset((XXH64_state_t*)state, 0);
            };
            pAlgFunctions->fpHSP_HashFinalize = [](void* state) {
                XXH64_freeState((XXH64_state_t*)state);
            };
            pAlgFunctions->fpHSP_HashClone = [](void* state) -> void* {
                auto clone = XXH64_createState();
                XXH64_copyState(clone, (XXH64_state_t*)state);
                return clone;
            };
            return TRUE;
        }
    }

    if (AlgID == 2) {
        static const char16_t* hashName = (const char16_t*)L"xxHash3-64";

        static const GUID hashGuid{
            0x463db2cf, 0xe42d, 0x4691, { 0xe8, 0xfd, 0x18, 0x4b, 0xc6, 0xc7, 0xb3, 0x2a }
        };

        if (uMsg == HSPPFMsg_Hash_GetAlgInfo) {
            auto pAlgInfo = (PHSP_AlgInfo)wParam;
            pAlgInfo->BlockSizeOctets = 0;
            pAlgInfo->DigestSize = 8;
            pAlgInfo->szAlgName = hashName;
            return TRUE;
        }

        if (uMsg == HSPPFMsg_Hash_GetAlgInfoEx) {
            auto pAlgInfoEx = (PHSP_AlgInfoEx)wParam;
            pAlgInfoEx->eHSPAlgFlags = HSPAlgFlags_None;
            pAlgInfoEx->pGuid = &hashGuid;
            pAlgInfoEx->szAlgFileName = hashName;
            return TRUE;
        }

        if (uMsg == HSPPFMsg_Hash_GetAlgFunctions) {
            auto pAlgFunctions = (PHSP_AlgFunctions)wParam;
            pAlgFunctions->fpHSP_HashInitialize = [](uint32_t AlgID) -> void* {
                auto state = XXH3_createState();
                XXH3_64bits_reset(state);
                return state;
            };
            pAlgFunctions->fpHSP_HashUpdate = [](void* state, const uint8_t* data, rsize_t dataOctets) {
                XXH3_64bits_update((XXH3_state_t*)state, data, dataOctets);
            };
            pAlgFunctions->fpHSP_HashGetHex = [](void* state, uint8_t* digest, rsize_t getOctets) {
                auto hash = XXH3_64bits_digest((XXH3_state_t*)state);
                hash = std::byteswap(hash);
                memcpy_s(digest, getOctets, &hash, sizeof(hash));
            };
            pAlgFunctions->fpHSP_HashReset = [](void* state) {
                XXH3_64bits_reset((XXH3_state_t*)state);
            };
            pAlgFunctions->fpHSP_HashFinalize = [](void* state) {
                XXH3_freeState((XXH3_state_t*)state);
            };
            pAlgFunctions->fpHSP_HashClone = [](void* state) -> void* {
                auto clone = XXH3_createState();
                XXH3_copyState(clone, (XXH3_state_t*)state);
                return clone;
            };
            return TRUE;
        }
    }

    if (AlgID == 3) {
        static const char16_t* hashName = (const char16_t*)L"xxHash3-128";

        static const GUID hashGuid{
            0xc7c2d164, 0x39ed, 0x44fe, { 0xd7, 0xe0, 0xed, 0xd2, 0xf1, 0xa9, 0x20, 0x7c }
        };

        if (uMsg == HSPPFMsg_Hash_GetAlgInfo) {
            auto pAlgInfo = (PHSP_AlgInfo)wParam;
            pAlgInfo->BlockSizeOctets = 0;
            pAlgInfo->DigestSize = 16;
            pAlgInfo->szAlgName = hashName;
            return TRUE;
        }

        if (uMsg == HSPPFMsg_Hash_GetAlgInfoEx) {
            auto pAlgInfoEx = (PHSP_AlgInfoEx)wParam;
            pAlgInfoEx->eHSPAlgFlags = HSPAlgFlags_None;
            pAlgInfoEx->pGuid = &hashGuid;
            pAlgInfoEx->szAlgFileName = hashName;
            return TRUE;
        }

        if (uMsg == HSPPFMsg_Hash_GetAlgFunctions) {
            auto pAlgFunctions = (PHSP_AlgFunctions)wParam;
            pAlgFunctions->fpHSP_HashInitialize = [](uint32_t AlgID) -> void* {
                auto state = XXH3_createState();
                XXH3_128bits_reset(state);
                return state;
            };
            pAlgFunctions->fpHSP_HashUpdate = [](void* state, const uint8_t* data, rsize_t dataOctets) {
                XXH3_128bits_update((XXH3_state_t*)state, data, dataOctets);
            };
            pAlgFunctions->fpHSP_HashGetHex = [](void* state, uint8_t* digest, rsize_t getOctets) {
                auto hash = XXH3_128bits_digest((XXH3_state_t*)state);
                uint64_t tmp[2] = {
                    std::byteswap(hash.high64),
                    std::byteswap(hash.low64),
                };
                memcpy_s(digest, getOctets, tmp, sizeof(tmp));
            };
            pAlgFunctions->fpHSP_HashReset = [](void* state) {
                XXH3_128bits_reset((XXH3_state_t*)state);
            };
            pAlgFunctions->fpHSP_HashFinalize = [](void* state) {
                XXH3_freeState((XXH3_state_t*)state);
            };
            pAlgFunctions->fpHSP_HashClone = [](void* state) -> void* {
                auto clone = XXH3_createState();
                XXH3_copyState(clone, (XXH3_state_t*)state);
                return clone;
            };
            return TRUE;
        }
    }
    return FALSE;
}
