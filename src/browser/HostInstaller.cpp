/*
*  Copyright (C) 2017 Sami Vänttinen <sami.vanttinen@protonmail.com>
*
*  This program is free software: you can redistribute it and/or modify
*  it under the terms of the GNU General Public License as published by
*  the Free Software Foundation, either version 3 of the License, or
*  (at your option) any later version.
*
*  This program is distributed in the hope that it will be useful,
*  but WITHOUT ANY WARRANTY; without even the implied warranty of
*  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*  GNU General Public License for more details.
*
*  You should have received a copy of the GNU General Public License
*  along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "HostInstaller.h"
#include <QDir>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QCoreApplication>

const QString HostInstaller::HOST_NAME = "com.varjolintu.keepassxc_browser";
const QStringList HostInstaller::ALLOWED_ORIGINS = QStringList()
    << "chrome-extension://iopaggbpplllidnfmcghoonnokmjoicf/"
    << "chrome-extension://fhakpkpdnjecjfceboihdjpfmgajebii/"
    << "chrome-extension://jaikbblhommnkeialomogohhdlndpfbi/";

const QStringList HostInstaller::ALLOWED_EXTENSIONS = QStringList()
    << "keepassxc-browser@sami.vanttinen";

#if defined(Q_OS_OSX)
    const QString HostInstaller::TARGET_DIR_CHROME = "/Library/Application Support/Google/Chrome/NativeMessagingHosts";
    const QString HostInstaller::TARGET_DIR_CHROMIUM = "/Library/Application Support/Chromium/NativeMessagingHosts";
    const QString HostInstaller::TARGET_DIR_FIREFOX = "/Library/Application Support/Mozilla/NativeMessagingHosts";
    const QString HostInstaller::TARGET_DIR_VIVALDI = "/Library/Application Support/Vivaldi/NativeMessagingHosts";
#elif defined(Q_OS_LINUX)
    const QString HostInstaller::TARGET_DIR_CHROME = "/.config/google-chrome/NativeMessagingHosts";
    const QString HostInstaller::TARGET_DIR_CHROMIUM = "/.config/chromium/NativeMessagingHosts";
    const QString HostInstaller::TARGET_DIR_FIREFOX = "/.mozilla/native-messaging-hosts";
    const QString HostInstaller::TARGET_DIR_VIVALDI = "/.config/vivaldi/NativeMessagingHosts";
#elif defined(Q_OS_WIN)
    const QString HostInstaller::TARGET_DIR_CHROME = "HKEY_CURRENT_USER\\Software\\Google\\Chrome\\NativeMessagingHosts";
    const QString HostInstaller::TARGET_DIR_CHROMIUM = "HKEY_CURRENT_USER\\Software\\Chromium\\NativeMessagingHosts";
    const QString HostInstaller::TARGET_DIR_FIREFOX = "HKEY_CURRENT_USER\\Software\\Mozilla\\NativeMessagingHosts";
    const QString HostInstaller::TARGET_DIR_VIVALDI = "HKEY_CURRENT_USER\\Software\\Vivaldi\\NativeMessagingHosts";
#endif

HostInstaller::HostInstaller()
{

}

bool HostInstaller::checkIfInstalled(const supportedBrowsers browser)
{
    QString fileName = getPath(browser);
#ifdef Q_OS_WIN
    QSettings settings(getTargetPath(browser), QSettings::NativeFormat);
    if (registryEntryFound(settings)) {
        return true;
    }
    return false;
#else
    if (QFile::exists(fileName)) {
        return true;
    }
    return false;
#endif
}

void HostInstaller::installBrowser(const supportedBrowsers browser, const bool enabled)
{
    if (enabled && !checkIfInstalled(browser)) {
        QJsonObject script = constructFile(browser);
#ifdef Q_OS_WIN
        // Create a registry key
        QSettings settings(getTargetPath(browser), QSettings::NativeFormat);
        if (!registryEntryFound(settings)) {
            settings.setValue("Default", getPath(browser));
        }
#endif
        // Install the .json file
        if (!saveFile(browser, script)) {

        }
    } else if (!enabled && checkIfInstalled(browser)) {
        // Uninstall the .json file
        QString fileName = getPath(browser);
        QFile::remove(fileName);
#ifdef Q_OS_WIN
        // Remove the registry entry
        QSettings settings(getTargetPath(browser), QSettings::NativeFormat);
        if (!registryEntryFound(settings)) {
            settings.remove("Default");
        }
#endif
    }
}

QString HostInstaller::getTargetPath(const supportedBrowsers browser)
{
    switch (browser) {
        case supportedBrowsers::CHROME:     return HostInstaller::TARGET_DIR_CHROME;
        case supportedBrowsers::CHROMIUM:   return HostInstaller::TARGET_DIR_CHROMIUM;
        case supportedBrowsers::FIREFOX:    return HostInstaller::TARGET_DIR_FIREFOX;
        case supportedBrowsers::VIVALDI:    return HostInstaller::TARGET_DIR_VIVALDI;
        default: return "";
    }
}

QString HostInstaller::getPath(const supportedBrowsers browser)
{
#ifdef Q_OS_WIN
    return QString("%1/%2.json").arg(QCoreApplication::applicationDirPath(), HostInstaller::HOST_NAME);
#endif
    QString path = getTargetPath(browser);
    return QString("%1%2/%3.json").arg(QDir::homePath(), path, HostInstaller::HOST_NAME);
}

QJsonObject HostInstaller::constructFile(const supportedBrowsers browser)
{
    QString path = QFileInfo(QCoreApplication::applicationFilePath()).absoluteFilePath();

    QJsonObject script;
    script["name"]          = HostInstaller::HOST_NAME;
    script["description"]   = "KeePassXC integration with Native Messaging support";
    script["path"]          = path;
    script["type"]          = "stdio";

    QJsonArray arr;
    if (browser == supportedBrowsers::FIREFOX) {
        for (const QString extension : HostInstaller::ALLOWED_EXTENSIONS) {
            arr.append(extension);
        }
        script["allowed_extensions"] = arr;
    } else {
        for (const QString origin : HostInstaller::ALLOWED_ORIGINS) {
            arr.append(origin);
        }
        script["allowed_origins"] = arr;
    }

    return script;
}

bool HostInstaller::registryEntryFound(const QSettings& settings){
    return !settings.value("Default").isNull();
}

bool HostInstaller::saveFile(const supportedBrowsers browser, const QJsonObject script)
{
    QString path = getPath(browser);
    QFile scriptFile(path);

    if (!scriptFile.open(QIODevice::WriteOnly)) {
        return false;
    }

    QJsonDocument doc(script);
    qint64 bytesWritten = scriptFile.write(doc.toJson());
    if (bytesWritten < 0) {
        return false;
    }

    return true;
}
