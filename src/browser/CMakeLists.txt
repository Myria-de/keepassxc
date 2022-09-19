#  Copyright (C) 2022 KeePassXC Team <team@keepassxc.org>
#
#  This program is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program.  If not, see <http://www.gnu.org/licenses/>.

if(WITH_XC_BROWSER)
    include_directories(${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})

    set(keepassxcbrowser_SOURCES
            BrowserAccessControlDialog.cpp
            BrowserAction.cpp
            BrowserEntryConfig.cpp
            BrowserEntrySaveDialog.cpp
            BrowserHost.cpp
            BrowserMessageBuilder.cpp
            BrowserSettingsPage.cpp
            BrowserSettingsWidget.cpp
            BrowserService.cpp
            BrowserSettings.cpp
            BrowserShared.cpp
            CustomTableWidget.cpp
            NativeMessageInstaller.cpp)

    if(WITH_XC_BROWSER_WEBAUTHN)
        # CBOR requires Qt 5.12
        if(Qt5Core_VERSION VERSION_LESS "5.12.0")
            message(FATAL_ERROR "Qt version 5.12.0 or higher is required for WebAuthn support")
        endif()

        list(APPEND keepassxcbrowser_SOURCES
                BrowserCbor.cpp
                BrowserWebAuthn.cpp
                BrowserWebAuthnConfirmationDialog.cpp)
    endif()

    add_library(keepassxcbrowser STATIC ${keepassxcbrowser_SOURCES})
    target_link_libraries(keepassxcbrowser Qt5::Core Qt5::Concurrent Qt5::Widgets Qt5::Network ${BOTAN_LIBRARIES})
endif()
