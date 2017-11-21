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
#include <QStandardPaths>
#include <QJsonArray>
#include <QJsonDocument>
#include <QCoreApplication>
#include <QMessageBox>

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
    const QString HostInstaller::TARGET_DIR_CHROME = "HKEY_CURRENT_USER\\Software\\Google\\Chrome\\NativeMessagingHosts\\" + HostInstaller::HOST_NAME;
    const QString HostInstaller::TARGET_DIR_CHROMIUM = "HKEY_CURRENT_USER\\Software\\Chromium\\NativeMessagingHosts\\" + HostInstaller::HOST_NAME;
    const QString HostInstaller::TARGET_DIR_FIREFOX = "HKEY_CURRENT_USER\\Software\\Mozilla\\NativeMessagingHosts\\" + HostInstaller::HOST_NAME;
    const QString HostInstaller::TARGET_DIR_VIVALDI = "HKEY_CURRENT_USER\\Software\\Vivaldi\\NativeMessagingHosts\\" + HostInstaller::HOST_NAME;
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

void HostInstaller::installBrowser(const supportedBrowsers browser, const bool enabled, const bool proxy, const QString location)
{
    if (enabled) {
 #ifdef Q_OS_WIN
         // Create a registry key
         QSettings settings(getTargetPath(browser), QSettings::NativeFormat);
         if (!registryEntryFound(settings)) {
             settings.setValue("Default", getPath(browser));
         }
 #endif
         // Always create the script file
         QJsonObject script = constructFile(browser, proxy, location);
         if (!saveFile(browser, script)) {
             QMessageBox::critical(0, tr("KeePassXC: Cannot save file!"),
                                        tr("Cannot save the Native Messaging script file."), QMessageBox::Ok);
         }
     } else {
         // Remove the script file
         QString fileName = getPath(browser);
         QFile::remove(fileName);
 #ifdef Q_OS_WIN
         // Remove the registry entry
         QSettings settings(getTargetPath(browser), QSettings::NativeFormat);
         if (registryEntryFound(settings)) {
             settings.remove("Default");
         }
 #endif
     }
}

void HostInstaller::updateBinaryPaths(const bool proxy, const QString location)
{
    for (int i = 0; i < 4; i++) {
        if (checkIfInstalled(static_cast<supportedBrowsers>(i))) {
            installBrowser(static_cast<supportedBrowsers>(i), true, proxy, location);
        }
    }
}

QString HostInstaller::getTargetPath(const supportedBrowsers browser)
{
    switch (browser) {
    case supportedBrowsers::CHROME:     return HostInstaller::TARGET_DIR_CHROME;
    case supportedBrowsers::CHROMIUM:   return HostInstaller::TARGET_DIR_CHROMIUM;
    case supportedBrowsers::FIREFOX:    return HostInstaller::TARGET_DIR_FIREFOX;
    case supportedBrowsers::VIVALDI:    return HostInstaller::TARGET_DIR_VIVALDI;
    default: return QString();
    }
}

QString HostInstaller::getBrowserName(const supportedBrowsers browser)
{
	switch (browser) {
    case supportedBrowsers::CHROME:     return "chrome";
    case supportedBrowsers::CHROMIUM:   return "chromium";
    case supportedBrowsers::FIREFOX:    return "firefox";
    case supportedBrowsers::VIVALDI:    return "vivaldi";
    default: return QString();
    }
}

QString HostInstaller::getPath(const supportedBrowsers browser)
{
#ifdef Q_OS_WIN
    // If portable settings file exists save the JSON scripts to application folder
    QString userPath;
    QString portablePath = QCoreApplication::applicationDirPath() + "/keepassxc.ini";
    if (QFile::exists(portablePath)) {
        userPath = QCoreApplication::applicationDirPath();
    } else {
        userPath = QDir::fromNativeSeparators(QStandardPaths::writableLocation(QStandardPaths::DataLocation));
    }

    QString winPath = QString("%1/%2_%3.json").arg(userPath, HostInstaller::HOST_NAME, getBrowserName(browser));
    winPath.replace("/","\\");
    return winPath;
#endif
    QString path = getTargetPath(browser);
    return QString("%1%2/%3.json").arg(QDir::homePath(), path, HostInstaller::HOST_NAME);
}

QString HostInstaller::getInstallDir(const supportedBrowsers browser)
{
#ifdef Q_OS_WIN
    return QCoreApplication::applicationDirPath();
#endif
    QString path = getTargetPath(browser);
    return QString("%1%2").arg(QDir::homePath(), path);
}

QJsonObject HostInstaller::constructFile(const supportedBrowsers browser, const bool proxy, const QString location)
{
    QString path;
    if (proxy) {
        if (!location.isEmpty()) {
            path = location;
        } else {
            path = QFileInfo(QCoreApplication::applicationFilePath()).absolutePath();
            path.append("/keepassxc-proxy");
#ifdef Q_OS_WIN
            path.append(".exe");
#endif
        }
    } else {
        path = QFileInfo(QCoreApplication::applicationFilePath()).absoluteFilePath();
    }
#ifdef Q_OS_WIN
    path.replace("/","\\");
#endif

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

bool HostInstaller::registryEntryFound(const QSettings& settings)
{
    return !settings.value("Default").isNull();
}

bool HostInstaller::saveFile(const supportedBrowsers browser, const QJsonObject script)
{
    QString path = getPath(browser);
    QString installDir = getInstallDir(browser);
    QDir dir(installDir);
    if (!dir.exists()) {
        QDir().mkpath(installDir);
    }

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
