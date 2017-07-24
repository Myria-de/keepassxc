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

#ifndef HOSTINSTALLER_H
#define HOSTINSTALLER_H

#include <QObject>
#include <QJsonObject>
#include <QSettings>

class HostInstaller : public QObject
{
    Q_OBJECT

public:
    enum supportedBrowsers {
        CHROME = 0,
        CHROMIUM = 1,
        FIREFOX = 2,
        VIVALDI = 3
    };

public:
    HostInstaller();
    bool checkIfInstalled(const supportedBrowsers browser);
    void installBrowser(const supportedBrowsers browser, const bool enabled);

private:
    QString     getTargetPath(const supportedBrowsers browser);
    QString     getPath(const supportedBrowsers browser);
    QString     getInstallDir(const supportedBrowsers browser);
    QJsonObject constructFile(const supportedBrowsers browser);
    bool        registryEntryFound(const QSettings& settings);
    bool        saveFile(const supportedBrowsers browser, const QJsonObject script);

private:
    static const QString HOST_NAME;
    static const QStringList ALLOWED_EXTENSIONS;
    static const QStringList ALLOWED_ORIGINS;
    static const QString TARGET_DIR_CHROME;
    static const QString TARGET_DIR_CHROMIUM;
    static const QString TARGET_DIR_FIREFOX;
    static const QString TARGET_DIR_VIVALDI;
};

#endif // HOSTINSTALLER_H
