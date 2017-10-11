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
#include "BrowserService.h"
#include "gui/DatabaseTabWidget.h"
#ifndef Q_OS_WIN
#include <boost/asio.hpp>
#include <boost/bind.hpp>
#endif
#include <QUdpSocket>
#include <atomic>

#include "BrowserClients.h"

class NativeMessagingHost : public QObject
{
    Q_OBJECT

public:
    explicit    NativeMessagingHost(DatabaseTabWidget* parent = 0);
    ~NativeMessagingHost();
    int         init();
    void        run();
    void        stop();

private:
    void        readLine();
    void        readMessages();
#ifndef Q_OS_WIN
    void        readHeader();
    void        readBody(const size_t len);
    void        handleHeader(const boost::system::error_code ec, const size_t br);
#endif
    void        sendReply(const QJsonObject json, const quint16 clientPort = 0);

signals:
    void        quit();

public slots:
    void        removeSharedEncryptionKeys();
    void        removeStoredPermissions();

private slots:
    void        readDatagrams();

private:
     std::atomic<bool>                      m_interrupted;
#ifndef Q_OS_WIN
     boost::asio::io_service                m_io_service;
     boost::asio::posix::stream_descriptor  m_sd;
#endif
     QFuture<void>                          m_fut;
     QMutex                                 m_mutex;
     bool                                   m_running;
     QUdpSocket                             m_udpSocket;
     quint16                                m_localPort;
     BrowserClients                         m_browserClients;
     DatabaseTabWidget*                     m_dbTabWidget;
     std::array<char, 4>                    m_headerBuf;
};

#endif // NATIVEMESSAGINGHOST_H
