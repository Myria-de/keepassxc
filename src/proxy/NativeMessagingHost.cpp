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

#include <QCoreApplication>
#include "NativeMessagingHost.h"

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
#endif

NativeMessagingHost::NativeMessagingHost()
{
#ifndef Q_OS_WIN
    m_notifier.reset(new QSocketNotifier(fileno(stdin), QSocketNotifier::Read, this));
    connect(m_notifier.data(), SIGNAL(activated(int)), this, SLOT(newMessage()));
    pid_t pid = getpid();
    QString client = "/tmp/kpxc_client." + QString::number(pid);
    QFile::remove(client);
#endif
    m_localSocket = new QLocalSocket();
#ifdef Q_OS_WIN
    m_localSocket->connectToServer("kpxc_server");
    m_running.store(true);
    m_future = QtConcurrent::run(this, &NativeMessagingHost::readNativeMessages);
#else
    m_localSocket->connectToServer("/tmp/kpxc_server");
#endif
    connect(m_localSocket, SIGNAL(readyRead()), this, SLOT(newLocalMessage()));
    connect(m_localSocket, SIGNAL(disconnected()), this, SLOT(deleteSocket()));
    connect(m_localSocket, SIGNAL(stateChanged(QLocalSocket::LocalSocketState)), this, SLOT(socketStateChanged(QLocalSocket::LocalSocketState)));
}

NativeMessagingHost::~NativeMessagingHost()
{
#ifdef Q_OS_WIN
    m_future.waitForFinished();
#endif
}

void NativeMessagingHost::newMessage()
{
#ifndef Q_OS_LINUX
#if defined Q_OS_MAC || defined Q_OS_UNIX
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
#endif
#elif defined Q_OS_LINUX
    int fd = epoll_create(5);
    struct epoll_event event;
    event.events = EPOLLIN;
    event.data.fd = 0;
    epoll_ctl(fd, EPOLL_CTL_ADD, 0, &event);

    epoll_wait(fd, &event, 1, 5000);
#endif

    quint32 length = 0;
    std::cin.read(reinterpret_cast<char*>(&length), 4);

    if (!std::cin.eof() && length > 0)
    {
        QByteArray arr;
        for (quint32 i = 0; i < length; i++) {
            arr.append(getchar());
        }

        if (arr.length() > 0 && m_localSocket) {
            m_localSocket->write(arr.constData(), arr.length());
            m_localSocket->flush();
        }
    } else {
    	QCoreApplication::quit();
    }

#ifndef Q_OS_WIN
    ::close(fd);
#endif
}

#ifdef Q_OS_WIN
void NativeMessagingHost::readNativeMessages()
{
    quint32 length = 0;
    while (m_running.load() && !std::cin.eof()) {
        length = 0;
        std::cin.read(reinterpret_cast<char*>(&length), 4);
        QByteArray arr;

        if (length > 0) {
            for (quint32 i = 0; i < length; i++) {
                arr.append(getchar());
            }

            if (arr.length() > 0 && m_localSocket && m_localSocket->state() == QLocalSocket::ConnectedState) {
                m_localSocket->write(arr.constData(), arr.length());
                m_localSocket->flush();
            }
        } else {
            break;
        }

        QThread::msleep(1);
    }
}
#endif

void NativeMessagingHost::newLocalMessage()
{
    if (m_localSocket && m_localSocket->bytesAvailable() > 0) {
        QByteArray arr = m_localSocket->readAll();
        if (arr.length() > 0) {
           sendReply(arr);
        }
    }
}

void NativeMessagingHost::sendReply(const QString& reply)
{
    if (!reply.isEmpty()) {
        uint len = reply.length();
        std::cout << char(((len>>0) & 0xFF)) << char(((len>>8) & 0xFF)) << char(((len>>16) & 0xFF)) << char(((len>>24) & 0xFF));
        std::cout << reply.toStdString() << std::flush;
    }
}

void NativeMessagingHost::deleteSocket()
{
    if (m_notifier) {
        m_notifier->setEnabled(false);
    }
    m_localSocket->deleteLater();
    QCoreApplication::quit();
}

void NativeMessagingHost::socketStateChanged(QLocalSocket::LocalSocketState socketState)
{
    if (socketState == QLocalSocket::UnconnectedState || socketState == QLocalSocket::ClosingState) {
        m_running.testAndSetOrdered(true, false);
    }
}
