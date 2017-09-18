if(WITH_XC_BROWSER)
    include_directories(${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})

    if(NOT MINGW)
	    find_package(Boost 1.54 COMPONENTS system REQUIRED)
	    include_directories(${Boost_INCLUDE_DIR})
	    link_directories(${Boost_LIBRARY_DIRS})
	    set(Boost_USE_STATIC_LIBS           OFF)
	    set(Boost_USE_MULTITHREADED         ON)
	    set(BOOST_ALL_DYN_LINK              ON)
  	endif()

    find_package(sodium 1.0.12 REQUIRED)
    if(SODIUM_FOUND)
        include_directories(${sodium_INCLUDE_DIR})
        set(sodium_INCLUDE_EXTRAS "${sodium_INCLUDE_DIR}/sodium")
        include_directories(${sodium_INCLUDE_EXTRAS})
        set(pkg_config_libs_private "${pkg_config_libs_private} -lsodium")
    else()
        message(FATAL_ERROR "libsodium is not installed. Install it, then run CMake again")
    endif()

    set(keepassbrowser_SOURCES
        BrowserAccessControlDialog.cpp
        BrowserSettings.cpp
        BrowserOptionDialog.cpp
        BrowserService.cpp
        BrowserEntryConfig.cpp
        BrowserAction.cpp
        NativeMessagingHost.cpp
        HostInstaller.cpp
        Variant.cpp
    )
    set(keepassbrowser_FORMS
        BrowserAccessControlDialog.ui
        BrowserOptionDialog.ui
    )

    qt5_wrap_ui(keepassbrowser_SOURCES ${keepassbrowser_FORMS})

    add_library(keepassbrowser STATIC ${keepassbrowser_SOURCES})
    target_link_libraries(keepassbrowser Qt5::Core Qt5::Concurrent Qt5::Widgets Qt5::Network ${sodium_LIBRARY_RELEASE} ${Boost_SYSTEM_LIBRARY})
endif()
