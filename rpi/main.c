#include <stdio.h>
#include <string.h>
#include <vanilla.h>

#include "config.h"
#include "menu/menu.h"
#include "platform.h"
#include "ui/ui.h"
#include "ui/ui_sdl.h"

#ifdef __vita__
#include <psp2/sysmodule.h>
#include <psp2/kernel/threadmgr.h>
#include <psp2/kernel/processmgr.h>
#include <psp2/net/net.h>
#include <psp2/net/netctl.h>
#include <psp2/kernel/sysmem.h>
#endif

#if 0 // Vita resolution
#define SCREEN_WIDTH    960
#define SCREEN_HEIGHT   544
#else // Gamepad resolution
#define SCREEN_WIDTH    854
#define SCREEN_HEIGHT   480
#endif

#if !defined(ANDROID) && !defined(_WIN32)
#define SDL_main main
#endif

#include "game/game_main.h"
#include "pipemgmt.h"

#ifdef __vita__
unsigned int _newlib_heap_size_user = 200 * 1024 * 1024;
#include <psp2/power.h>
#endif

int SDL_main(int argc, const char **argv)
{
    // Default to full screen unless "-w" is specified
    int fs = 1;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-w")) {
            fs = 0;
        }
    }

#ifdef __vita__
    scePowerSetArmClockFrequency(444);
    scePowerSetBusClockFrequency(222);
    scePowerSetGpuClockFrequency(222);
    scePowerSetGpuXbarClockFrequency(166);
#endif
    
    vanilla_install_logger(vpilog_va);

#ifdef __vita__
    int ret0 = 0;
    if (sceSysmoduleIsLoaded(SCE_SYSMODULE_NET) != SCE_SYSMODULE_LOADED)
	    ret0 = sceSysmoduleLoadModule(SCE_SYSMODULE_NET);

    if (ret0 < 0) {
        vpilog("Failed to load SCE_SYSMODULE_NET: 0x%08X\n", ret0);
        goto end;
    } else {
        vpilog("SCE_SYSMODULE_NET loaded successfully.\n");
    }

    if (sceNetShowNetstat() == SCE_NET_ERROR_ENOTINIT) {
        SceNetInitParam netInitParam;
        int size = 1 * 1024 * 1024; // 1MB
        netInitParam.memory = malloc(size);
        netInitParam.size = size;
        netInitParam.flags = 0;
        ret0 = sceNetInit(&netInitParam);
        vpilog("sceNetInit(): 0x%08X\n", ret0);
    } else {
        vpilog("Net is already initialized.\n");
    }

    ret0 = sceNetCtlInit();
    vpilog("sceNetCtlInit(): 0x%08X\n", ret0);
    
    SceNetCtlInfo netCtlInfo;
    ret0 = sceNetCtlInetGetInfo(SCE_NETCTL_INFO_GET_IP_ADDRESS, &netCtlInfo);
    vpilog("sceNetCtlInetGetInfo(): 0x%08X\n", ret0);

    SceNetInAddr ip_addr;
    if (ret0 >= 0) {
        ret0 = sceNetInetPton(SCE_NET_AF_INET, netCtlInfo.ip_address, &ip_addr);
        vpilog("sceNetInetPton()(0x%08X): 0x%08X\n", ip_addr.s_addr, ret0);
        if (ret0 >= 0) {
            vpilog("IP Address: %s\n", netCtlInfo.ip_address);
            VANILLA_VITA_ADDRESS = ip_addr.s_addr;
        } else {
            vpilog("Failed to convert IP address: 0x%08X\n", ret0);
        }
    } else {
        vpilog("Failed to get IP address: 0x%08X\n", ret0);
    }

end:
    vpilog("Vita Net initialization end.\n");
#endif

    // Load config
    vpi_config_init();

    // Initialize UI system
    vui_context_t *vui = vui_alloc(SCREEN_WIDTH, SCREEN_HEIGHT);

#ifdef __vita__
#define ALIGN(x, a)          (((x) + ((a)-1)) & ~((a)-1))
    SceUID mem = sceKernelAllocMemBlock("prevent_sdl", SCE_KERNEL_MEMBLOCK_TYPE_USER_CDRAM_RW, ALIGN(SCREEN_WIDTH * SCREEN_HEIGHT * 4 * 16, 256 * 1024), NULL);
#endif

    // Initialize SDL2
    int ret = 1;
    if (vui_init_sdl(vui, fs)) {
        vpilog("Failed to initialize VUI\n");
        goto exit;
    }

    vpi_menu_init(vui);

#ifdef __vita__
    sceKernelFreeMemBlock(mem);
#endif

    while (vui_update_sdl(vui)) {
    }

    ret = 0;

    vpi_stop_pipe();

exit:
    vui_close_sdl(vui);

    vui_free(vui);

    vpi_config_free();

    return ret;
}