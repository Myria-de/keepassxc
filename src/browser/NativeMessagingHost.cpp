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

#include <QMutexLocker>
#include <QtNetwork>
#include <iostream>
#include "NativeMessagingHost.h"
#include "BrowserSettings.h"

#ifdef Q_OS_WIN
#include <fcntl.h>
#include <io.h>
#endif

#ifndef Q_OS_WIN
using namespace boost::asio;
using boost::system::error_code;

namespace boost
{
#ifdef BOOST_NO_EXCEPTIONS
void throw_exception(std::exception const& e) {
    std::cout << e.what();
};
#endif
}
#endif

NativeMessagingHost::NativeMessagingHost(DatabaseTabWidget* parent) :
   m_browserAction(parent),
#ifndef Q_OS_WIN
    m_sd(m_io_service, ::dup(STDIN_FILENO)),
#endif
    m_mutex(QMutex::Recursive),
    m_running(false),
    m_peerPort(0),
    m_localPort(19700)
{
#ifdef Q_OS_WIN
    _setmode(_fileno(stdin), _O_BINARY);
    _setmode(_fileno(stdout), _O_BINARY);
    m_interrupted = false;
#endif
    if (BrowserSettings::isEnabled() && !m_running) {
        run();
    }
}

NativeMessagingHost::~NativeMessagingHost()
{
    stop();
}

int NativeMessagingHost::init()
{
    QMutexLocker locker(&m_mutex);
    return m_browserAction.init();
}

void NativeMessagingHost::run()
{
    QMutexLocker locker(&m_mutex);
    if (!m_running) {
        if (init() == -1) {
            return;
        }

        m_running = true;
        m_fut = QtConcurrent::run(this, &NativeMessagingHost::readNativeMessages);
    }

    if (BrowserSettings::supportBrowserProxy()) {
        m_localPort = BrowserSettings::udpPort();
        m_udpSocket.bind(QHostAddress::LocalHost, m_localPort, QUdpSocket::DontShareAddress);
        connect(&m_udpSocket, SIGNAL(readyRead()), this, SLOT(readDatagrams()));
    } else {
        m_udpSocket.close();
    }
}

void NativeMessagingHost::stop()
{
    QMutexLocker locker(&m_mutex);
    m_udpSocket.close();

#ifdef Q_OS_WIN
    m_interrupted = true;
#else
    if (m_sd.is_open()) {
        m_sd.cancel();
        m_sd.close();
    }

    if (!m_io_service.stopped()) {
        m_io_service.stop();
    }
#endif

    m_fut.waitForFinished();
    m_running = false;
}

void NativeMessagingHost::readDatagrams()
{
    QByteArray dgram;

    while (m_udpSocket.hasPendingDatagrams()) {
        dgram.resize(m_udpSocket.pendingDatagramSize());
        m_udpSocket.readDatagram(dgram.data(), dgram.size(), &m_peerAddr, &m_peerPort);
    }

    QMutexLocker locker(&m_mutex);
    QJsonObject response = m_browserAction.readResponse(dgram);
    sendReply(response);
}

// Windows only
void NativeMessagingHost::readMessages()
{
    quint32 length = 0;
    while (!m_interrupted) {
        length = 0;
        std::cin.read(reinterpret_cast<char*>(&length), 4);
        QByteArray arr;
        for (quint32 i = 0; i < length; i++) {
            arr.append(getchar());
        }
        QJsonObject response = m_browserAction.readResponse(arr);
        sendReply(response);
        QThread::usleep(10);
    }
}

#ifndef Q_OS_WIN
void NativeMessagingHost::readHeader(boost::asio::posix::stream_descriptor& sd)
{
    std::array<char, 4> buf;
    async_read(sd, buffer(buf, buf.size()), transfer_at_least(1), [&](error_code ec, size_t br) {
        if (!ec && br >= 1) {
            uint len = 0;
            for (int i = 0; i < 4; i++) {
                uint rc = buf.at(i);
                len = len | (rc << i*8);
            }
            readBody(sd, len);
        }
    });
}

void NativeMessagingHost::readBody(boost::asio::posix::stream_descriptor& sd, const size_t len)
{
    std::array<char, MESSAGE_LENGTH> buf;
    async_read(sd, buffer(buf, len), transfer_at_least(1), [&](error_code ec, size_t br) {
        if (!ec && br > 0) {
            QByteArray arr(buf.data(), br);
            QJsonObject response = m_browserAction.readResponse(arr);
            sendReply(response);
            readHeader(sd);
        }
    });
}
#endif

void NativeMessagingHost::readNativeMessages()
{
#ifdef Q_OS_WIN
    m_interrupted = false;
    readMessages();
#else
    // Read the message header
    readHeader(m_sd);
    m_io_service.run();
#endif
}

void NativeMessagingHost::sendReply(const QJsonObject json)
{
    if (!json.isEmpty()) {
        QString reply(QJsonDocument(json).toJson(QJsonDocument::Compact));
        uint len = reply.length();

        std::cout << char(((len>>0) & 0xFF))
                    << char(((len>>8) & 0xFF))
                    << char(((len>>16) & 0xFF))
                    << char(((len>>24) & 0xFF));
        std::cout << reply.toStdString() << std::flush;

        if (BrowserSettings::supportBrowserProxy()) {
            QMutexLocker locker(&m_mutex);
            m_udpSocket.writeDatagram(reply.toUtf8(), m_peerAddr, m_peerPort);
        }
    }
}

void NativeMessagingHost::removeSharedEncryptionKeys()
{
    QMutexLocker locker(&m_mutex);
    m_browserAction.removeSharedEncryptionKeys();
}

void NativeMessagingHost::removeStoredPermissions()
{
    QMutexLocker locker(&m_mutex);
    m_browserAction.removeStoredPermissions();
}
