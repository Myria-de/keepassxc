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

#ifndef NATIVEMESSAGINGHOST_H
#define NATIVEMESSAGINGHOST_H

#include <QObject>
#include <QJsonObject>
#include <QJsonDocument>
#include <QFuture>
#include <QtConcurrent/QtConcurrent>
#include <QMutex>
#include <QSocketNotifier>
#include <QLocalServer>
#include <atomic>
#include "BrowserClients.h"
#include "BrowserService.h"
#include "gui/DatabaseTabWidget.h"

class NativeMessagingHost : public QObject
{
    Q_OBJECT

    typedef QList<QLocalSocket*> SocketList;

public:
    explicit    NativeMessagingHost(DatabaseTabWidget* parent = 0);
    ~NativeMessagingHost();
    int         init();
    void        run();
    void        stop();

private:
    void        readNativeMessages();
    void        sendReply(const QJsonObject& json);
    void        sendReplyToAllClients(const QJsonObject& json);
    QString     jsonToString(const QJsonObject& json) const;

signals:
    void        quit();

public slots:
    void        removeSharedEncryptionKeys();
    void        removeStoredPermissions();

private slots:
    void        databaseLocked();
    void        databaseUnlocked();
    void        newLocalConnection();
    void        newNativeMessage();
    void        newLocalMessage();
    void        disconnectSocket();

private:
    std::atomic_bool                m_running;
    QMutex                          m_mutex;
    BrowserClients                  m_browserClients;
    BrowserService                  m_browserService;
    QSharedPointer<QSocketNotifier> m_notifier;
    QSharedPointer<QLocalServer>    m_localServer;
    QFuture<void>                   m_future;
    SocketList                      m_socketList;
};

#endif // NATIVEMESSAGINGHOST_H
