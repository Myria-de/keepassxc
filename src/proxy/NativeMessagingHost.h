/*
*  Copyright (C) 2017 KeePassXC Team <team@keepassxc.org>
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
#include <QLocalSocket>
#include <QSharedPointer>
#include <QSocketNotifier>
#include <QFile>
#include <QFuture>
#include <QtConcurrent/QtConcurrent>
#include <QAtomicInteger>
#include <iostream>
#include <unistd.h>

class NativeMessagingHost : public QObject
{
    Q_OBJECT
public:
    NativeMessagingHost();
    ~NativeMessagingHost();

public slots:
    void newMessage();
    void newLocalMessage();
    void deleteSocket();
    void socketStateChanged(QLocalSocket::LocalSocketState socketState);

private:
    void readStdIn(const quint32 length);
    void readNativeMessages();
    void sendReply(const QString& reply);

private:
    QSharedPointer<QSocketNotifier>         m_notifier;
    QLocalSocket*                           m_localSocket;
    QFuture<void>                           m_future;
    QAtomicInteger<quint8>                  m_running;
};

#endif // NATIVEMESSAGINGHOST_H
