cmake_minimum_required(VERSION 3.16)

if(NOT DEFINED CMAKE_TOOLCHAIN_FILE)
  if(DEFINED ENV{VITASDK})
    set(CMAKE_TOOLCHAIN_FILE "$ENV{VITASDK}/share/vita.toolchain.cmake" CACHE PATH "toolchain file")
  else()
    message(FATAL_ERROR "Please define VITASDK to point to your SDK path!")
  endif()
endif()

project(vita-vanilla)
include("${VITASDK}/share/vita.cmake" REQUIRED)

set(VITA_APP_NAME "Vita Vanilla")
set(VITA_TITLEID  "VWIIU0001")
set(VITA_VERSION  "01.00")

list(APPEND VANILLA_PI_SRC
    config.c
    def.c
    # drm.c
    lang.c
    #game/game_decode_ffmpeg.c
    game/game_decode.c
    game/game_main.c
    main.c
    menu/menu.c
    menu/menu_common.c
    menu/menu_connection.c
    menu/menu_delete.c
    menu/menu_edit.c
    menu/menu_game.c
    menu/menu_gamepad.c
    menu/menu_main.c
    menu/menu_region.c
    menu/menu_rename.c
    menu/menu_settings.c
    menu/menu_sync.c
    pipemgmt.c
    platform.c
    ui/ui.c
    ui/ui_anim.c
    ui/ui_sdl.c
    ui/ui_util.c
    ui/ui_util.h

    # vita/common/debugScreen.c
)

add_executable(${PROJECT_NAME} ${VANILLA_PI_SRC})
install(TARGETS ${PROJECT_NAME})

find_package(SDL2 REQUIRED)
find_package(LibXml2 REQUIRED)
find_package(FFmpeg REQUIRED COMPONENTS avformat avcodec avutil swscale)
find_package(Freetype REQUIRED)
find_package(MbedTLS REQUIRED)

#find_package(PkgConfig REQUIRED)
#set(CMAKE_PREFIX_PATH "${CMAKE_SOURCE_DIR}/psv/ffmpeg/pkg/ffmpeg/usr/local/vitasdk/arm-vita-eabi/lib/pkgconfig")
#pkg_check_modules(avformat REQUIRED NO_CMAKE_PATH IMPORTED_TARGET libavformat)
#pkg_check_modules(avcodec REQUIRED NO_CMAKE_PATH IMPORTED_TARGET libavcodec)
#pkg_check_modules(avutil REQUIRED NO_CMAKE_PATH IMPORTED_TARGET libavutil)
#pkg_check_modules(swscale REQUIRED NO_CMAKE_PATH IMPORTED_TARGET libswscale)

target_link_libraries(${PROJECT_NAME} PRIVATE
    vanilla
    ${LIBXML2_LIBRARIES}

    SDL2::SDL2

    SDL2_ttf
    ${FREETYPE_LIBRARIES}

    SDL2_image
    webp
    webpdemux
    png
    bz2


    FFmpeg::avformat
    FFmpeg::avcodec
    FFmpeg::avutil
    FFmpeg::swscale
    mp3lame
    swresample
    MbedTLS::mbedtls

    pthread
    m
    z

    # SceDisplay_stub # debugScreen
    SceCtrl_stub
    SceNet_stub
    SceNetCtl_stub
    SceSysmodule_stub

    SceAudiodec_stub
    SceVideodec_stub
    SceCodecEngine_stub
)

target_include_directories(${PROJECT_NAME} PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/../lib"
    "${CMAKE_CURRENT_SOURCE_DIR}"
    "${CMAKE_CURRENT_SOURCE_DIR}/.."
    "${CMAKE_CURRENT_SOURCE_DIR}/vita/common"
    "${LIBXML2_INCLUDE_DIR}"
    "${FREETYPE_INCLUDE_DIRS}"
)

set(VITA_MKSFOEX_FLAGS "-d ATTRIBUTE2=12")
vita_create_self(eboot.bin ../bin/vita-vanilla)
vita_create_vpk(vita-vanilla.vpk ${VITA_TITLEID} eboot.bin
  VERSION ${VITA_VERSION}
  NAME ${VITA_APP_NAME}

  FILE assets/font/OFL.txt assets/font/OFL.txt
  FILE assets/font/system.ttf assets/font/system.ttf

  FILE assets/tex/backspace_black.svg assets/tex/backspace_black.svg
  FILE assets/tex/backspace.svg assets/tex/backspace.svg
  FILE assets/tex/checkmark.svg assets/tex/checkmark.svg
  FILE assets/tex/club_black.svg assets/tex/club_black.svg
  FILE assets/tex/club_white.svg assets/tex/club_white.svg
  FILE assets/tex/club.svg assets/tex/club.svg
  FILE assets/tex/diamond_black.svg assets/tex/diamond_black.svg
  FILE assets/tex/diamond_white.svg assets/tex/diamond_white.svg
  FILE assets/tex/diamond.svg assets/tex/diamond.svg
  FILE assets/tex/edit.svg assets/tex/edit.svg
  FILE assets/tex/gamepad.svg assets/tex/gamepad.svg
  FILE assets/tex/heart_black.svg assets/tex/heart_black.svg
  FILE assets/tex/heart_white.svg assets/tex/heart_white.svg
  FILE assets/tex/heart.svg assets/tex/heart.svg
  FILE assets/tex/settings.png assets/tex/settings.png
  FILE assets/tex/settings2.png assets/tex/settings2.png
  FILE assets/tex/spade_black.svg assets/tex/spade_black.svg
  FILE assets/tex/spade_white.svg assets/tex/spade_white.svg
  FILE assets/tex/spade.svg assets/tex/spade.svg
)
