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

#include <QMutexLocker>
#include <QtNetwork>
#include <iostream>
#include "sodium.h"
#include "NativeMessagingHost.h"
#include "BrowserSettings.h"

#ifndef Q_OS_LINUX
#if defined Q_OS_MAC || defined Q_OS_UNIX
#include <sys/types.h>
#include <sys/event.h>
#include <sys/time.h>
#include <unistd.h>
#endif
#endif

#ifdef Q_OS_LINUX
#include <sys/epoll.h>
#include <unistd.h>
#endif

#ifdef Q_OS_WIN
#include <fcntl.h>
#include <io.h>
#endif

NativeMessagingHost::NativeMessagingHost(DatabaseTabWidget* parent) :
    m_mutex(QMutex::Recursive),
    m_browserClients(m_browserService),
    m_browserService(parent)
{
#ifndef Q_OS_WIN
    m_notifier.reset(new QSocketNotifier(fileno(stdin), QSocketNotifier::Read, this));
    connect(m_notifier.data(), SIGNAL(activated(int)), this, SLOT(newNativeMessage()));
#endif
    m_localServer.reset(new QLocalServer(this));
    m_localServer->setSocketOptions(QLocalServer::UserAccessOption);
#ifdef Q_OS_WIN
    m_running.store(false);
    _setmode(_fileno(stdin), _O_BINARY);
    _setmode(_fileno(stdout), _O_BINARY);
#endif
    if (BrowserSettings::isEnabled() && !m_running) {
        run();
    }

    connect(&m_browserService, SIGNAL(databaseLocked()), this, SLOT(databaseLocked()));
    connect(&m_browserService, SIGNAL(databaseUnlocked()), this, SLOT(databaseUnlocked()));
}

NativeMessagingHost::~NativeMessagingHost()
{
    stop();
}

int NativeMessagingHost::init()
{
    QMutexLocker locker(&m_mutex);
    return sodium_init();
}

void NativeMessagingHost::run()
{
    QMutexLocker locker(&m_mutex);
    if (!m_running.load() && init() == -1) {
        return;
    }

    // Update KeePassXC/keepassxc-proxy binary paths to Native Messaging scripts
    if (BrowserSettings::updateBinaryPath()) {
        BrowserSettings::updateBinaryPaths(BrowserSettings::useCustomProxy() ? BrowserSettings::customProxyLocation() : "");
    }

    m_running.store(true);
#ifdef Q_OS_WIN
    m_future = QtConcurrent::run(this, &NativeMessagingHost::readNativeMessages);
#endif

    if (BrowserSettings::supportBrowserProxy()) {
#ifndef Q_OS_WIN
        QString serverPath = "/tmp/kpxc_server";
#else
        QString serverPath = "kpxc_server";
#endif
        QFile::remove(serverPath);
        m_localServer->listen(serverPath);
        connect(m_localServer.data(), SIGNAL(newConnection()), this, SLOT(newLocalConnection()));
    } else {
        m_localServer->close();
    }
}

void NativeMessagingHost::stop()
{
    databaseLocked();
    QMutexLocker locker(&m_mutex);
    m_socketList.clear();
    m_running.testAndSetOrdered(true, false);
    m_future.waitForFinished();
    m_localServer->close();
}

void NativeMessagingHost::readStdIn(const quint32 length)
{
    QByteArray arr;
    arr.reserve(length);

    for (quint32 i = 0; i < length; ++i) {
        arr.append(getchar());
    }

    if (arr.length() > 0) {
        QMutexLocker locker(&m_mutex);
        sendReply(m_browserClients.readResponse(arr));
    }
}

void NativeMessagingHost::readNativeMessages()
{
#ifdef Q_OS_WIN
    quint32 length = 0;
	while (m_running.load() && !std::cin.eof()) {
		length = 0;
		std::cin.read(reinterpret_cast<char*>(&length), 4);
        readStdIn(length);
		QThread::msleep(1);
	}
#endif
}

void NativeMessagingHost::newNativeMessage()
{
#if defined(Q_OS_UNIX) && !defined(Q_OS_LINUX)
    struct kevent ev[1];
	struct timespec ts = { 5, 0 };

	int fd = kqueue();
	if (fd == -1) {
		m_notifier->setEnabled(false);
		return;
	}

	EV_SET(ev, fileno(stdin), EVFILT_READ, EV_ADD, 0, 0, NULL);
    if (kevent(fd, ev, 1, NULL, 0, &ts) == -1) {
    	m_notifier->setEnabled(false);
    	return;
    }

    int ret = kevent(fd, NULL, 0, ev, 1, &ts);
    if (ret < 1) {
    	m_notifier->setEnabled(false);
        ::close(fd);
        return;
    }
#elif defined Q_OS_LINUX
    int fd = epoll_create(5);

    struct epoll_event event;
    event.events = EPOLLIN;
    event.data.fd = 0;

    if (epoll_ctl(fd, EPOLL_CTL_ADD, 0, &event) != 0) {
        m_notifier->setEnabled(false);
        return;
    }

    if (epoll_wait(fd, &event, 1, 5000) < 1) {
    	m_notifier->setEnabled(false);
        ::close(fd);
        return;
    }
#endif

    quint32 length = 0;
    std::cin.read(reinterpret_cast<char*>(&length), 4);

    if (!std::cin.eof() &&length > 0)
    {
        readStdIn(length);
    }

#ifndef Q_OS_WIN
    ::close(fd);
#endif
}

void NativeMessagingHost::newLocalConnection()
{
    QLocalSocket* socket = m_localServer->nextPendingConnection();
    connect(socket, SIGNAL(readyRead()), this, SLOT(newLocalMessage()));
    connect(socket, SIGNAL(disconnected()), this, SLOT(disconnectSocket()));
}

void NativeMessagingHost::newLocalMessage()
{
    QLocalSocket* socket = qobject_cast<QLocalSocket*>(QObject::sender());

    if (!socket || socket->bytesAvailable() <= 0) {
        return;
    }

    QByteArray arr = socket->readAll();
    if (arr.length() <= 0) {
        return;
    }

    QMutexLocker locker(&m_mutex);
    if (!m_socketList.contains(socket)) {
        m_socketList.push_back(socket);
    }

    QString reply = jsonToString(m_browserClients.readResponse(arr));
    if (socket && socket->isValid() && socket->state() == QLocalSocket::ConnectedState) {
        socket->write(reply.toUtf8().constData(), reply.length()+1);
        socket->flush();
    }
}

void NativeMessagingHost::sendReply(const QJsonObject& json)
{
    if (!json.isEmpty()) {
        QString reply = jsonToString(json);
        uint len = reply.length();
        std::cout << char(((len>>0) & 0xFF)) << char(((len>>8) & 0xFF)) << char(((len>>16) & 0xFF)) << char(((len>>24) & 0xFF));
        std::cout << reply.toStdString() << std::flush;
    }
}

void NativeMessagingHost::sendReplyToAllClients(const QJsonObject& json)
{
    QString reply = jsonToString(json);
    QMutexLocker locker(&m_mutex);
    for (const auto socket : m_socketList) {
        if (socket && socket->isValid() && socket->state() == QLocalSocket::ConnectedState) {
            socket->write(reply.toUtf8().constData(), reply.length());
            socket->flush();
        }
    }
}

void NativeMessagingHost::disconnectSocket()
{
    QLocalSocket* socket(qobject_cast<QLocalSocket*>(QObject::sender()));
    QMutexLocker locker(&m_mutex);
    for (auto s : m_socketList) {
        if (s == socket) {
            m_socketList.removeOne(s);
        }
    }
}

QString NativeMessagingHost::jsonToString(const QJsonObject& json) const
{
    return QString(QJsonDocument(json).toJson(QJsonDocument::Compact));
}

void NativeMessagingHost::removeSharedEncryptionKeys()
{
    QMutexLocker locker(&m_mutex);
    m_browserService.removeSharedEncryptionKeys();
}

void NativeMessagingHost::removeStoredPermissions()
{
    QMutexLocker locker(&m_mutex);
    m_browserService.removeStoredPermissions();
}

void NativeMessagingHost::databaseLocked()
{
    QJsonObject response;
    response["action"] = "database-locked";
    sendReplyToAllClients(response);
}

void NativeMessagingHost::databaseUnlocked()
{
    QJsonObject response;
    response["action"] = "database-unlocked";
    sendReplyToAllClients(response);
}
