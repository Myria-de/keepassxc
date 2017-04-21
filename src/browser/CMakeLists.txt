if(WITH_XC_BROWSER)
    include_directories(${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})
    include_directories(${CMAKE_CURRENT_SOURCE_DIR}/libsodium/include)
    include_directories(${CMAKE_CURRENT_SOURCE_DIR}/libsodium/include/sodium)

    find_package(Sodium)
    if (SODIUM_FOUND)
        message(STATUS "libsodium found")
        include_directories(${SODIUM_INCLUDE_DIR})
        include_directories(${SODIUM_INCLUDE_DIR}/sodium)
        set(pkg_config_libs_private "${pkg_config_libs_private} -lsodium")
        message("sodium_FOUND = " "${sodium_FOUND}")
        message("sodium_INCLUDE_DIR = " "${sodium_INCLUDE_DIR}")
        message("sodium_LIBRARY_RELEASE = " "${sodium_LIBRARY_RELEASE}")
        message("sodium_LIBRARY_DEBUG = " "${sodium_LIBRARY_DEBUG}")
    else ()
        message(FATAL_ERROR "libsodium is not installed. Install it, then run CMake again")
    endif ()

    set(keepassbrowser_SOURCES
        BrowserAccessControlDialog.cpp
        ChromeListener.cpp
        BrowserPasswordGeneratorWidget.cpp
        BrowserSettings.cpp
        BrowserOptionDialog.cpp
    )
    set(keepassbrowser_FORMS
        BrowserAccessControlDialog.ui
        BrowserPasswordGeneratorWidget.ui
        BrowserOptionDialog.ui
    )

    qt5_wrap_ui(keepassbrowser_SOURCES ${keepassbrowser_FORMS})

    add_library(keepassbrowser STATIC ${keepassbrowser_SOURCES})
    target_link_libraries(keepassbrowser Qt5::Core Qt5::Concurrent Qt5::Widgets Qt5::Network ${sodium_LIBRARY_DEBUG})
endif()
