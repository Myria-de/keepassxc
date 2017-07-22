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

#ifndef CHROMELISTENER_H
#define CHROMELISTENER_H

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
#endif
#include <QUdpSocket>
#include <atomic>

class ChromeListener : public QObject
{
    Q_OBJECT

    enum {
        ERROR_KEEPASS_DATABASE_NOT_OPENED = 1,
        ERROR_KEEPASS_DATABASE_HASH_NOT_RECEIVED = 2,
        ERROR_KEEPASS_CLIENT_PUBLIC_KEY_NOT_RECEIVED = 3,
        ERROR_KEEPASS_CANNOT_DECRYPT_MESSAGE = 4,
        ERROR_KEEPASS_TIMEOUT_OR_NOT_CONNECTED = 5,
        ERROR_KEEPASS_ACTION_CANCELLED_OR_DENIED = 6,
        ERROR_KEEPASS_CANNOT_ENCRYPT_MESSAGE = 7,
        ERROR_KEEPASS_ASSOCIATION_FAILED = 8,
        ERROR_KEEPASS_KEY_CHANGE_FAILED = 9,
        ERROR_KEEPASS_ENCRYPTION_KEY_UNRECOGNIZED = 10,
        ERROR_KEEPASS_NO_SAVED_DATABASES_FOUND = 11
    };

public:
    explicit    ChromeListener(DatabaseTabWidget* parent = 0);
    ~ChromeListener();
    int         init();
    void        run();
    void        stop();

private:
    void        readResponse(const QByteArray& arr);
    void        readLine();
    void        readMessages();
#ifndef Q_OS_WIN
    void        readHeader(boost::asio::posix::stream_descriptor& sd);
    void        readBody(boost::asio::posix::stream_descriptor& sd, const size_t len);
#endif
    void        handleAction(const QJsonObject& json);
    void        handleGetDatabaseHash(const QJsonObject& json, const QString& action);
    void        handleChangePublicKeys(const QJsonObject& json, const QString& action);
    void        handleAssociate(const QJsonObject& json, const QString& action);
    void        handleTestAssociate(const QJsonObject& json, const QString& action);
    void        handleGetLogins(const QJsonObject& json, const QString& action);
    void        handleGeneratePassword(const QJsonObject& json, const QString& action);
    void        handleSetLogin(const QJsonObject& json, const QString& action);

    void        sendReply(const QJsonObject json);
    void        sendErrorReply(const QString& action, const int errorCode);
    QString     getErrorMessage(const int errorCode) const;

    QString     encrypt(const QString decrypted, const QString nonce) const;
    QByteArray  decrypt(const QString encrypted, const QString nonce) const;
    QJsonObject decryptMessage(const QString& message, const QString& nonce, const QString& action = QString());
    QString     getDataBaseHash();

signals:
    void        quit();

public slots:
    void        removeSharedEncryptionKeys();
    void        removeStoredPermissions();

private slots:
    void        readDatagrams();

private:
    static QString      getBase64FromKey(const uchar* array, const uint len);
    static QByteArray   getQByteArray(const uchar* array, const uint len);
    static QJsonObject  getJSonObject(const uchar* pArray, const uint len);
    static QJsonObject  getJSonObject(const QByteArray ba);
    static QByteArray   base64Decode(const QString str);

private:
     QString                                m_clientPublicKey;
     QString                                m_publicKey;
     QString                                m_secretKey;
     BrowserService                         m_service;
     std::atomic<bool>                      m_interrupted;
#ifndef Q_OS_WIN
     boost::asio::io_service                m_io_service;
     boost::asio::posix::stream_descriptor  m_sd;
#endif
     QFuture<void>                          m_fut;
     QMutex                                 m_mutex;
     bool                                   m_running;
     bool                                   m_associated;

     QUdpSocket                             m_udpSocket;
     QHostAddress                           m_peerAddr;
     quint16                                m_peerPort;
     quint16                                m_localPort;
};

#endif // CHROMELISTENER_H
