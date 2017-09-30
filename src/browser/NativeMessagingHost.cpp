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

#include <QJsonArray>
#include <QtCore/QCryptographicHash>
#include <QMutexLocker>
#include <QtNetwork>
#include <QDataStream>
#include <iostream>
#include "sodium.h"
#include "sodium/crypto_box.h"
#include "sodium/randombytes.h"
#include "NativeMessagingHost.h"
#include "BrowserSettings.h"
#include "config-keepassx.h"

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
    m_service(parent),
#ifndef Q_OS_WIN
    m_sd(m_io_service, ::dup(STDIN_FILENO)),
#endif
    m_mutex(QMutex::Recursive),
    m_running(false),
    m_associated(false),
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
    return sodium_init();
}

void NativeMessagingHost::run()
{
    QMutexLocker locker(&m_mutex);
    if (!m_running) {
        if (init() == -1) {
            return;
        }

        m_running = true;
        m_fut = QtConcurrent::run(this, &NativeMessagingHost::readLine);
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

    readResponse(dgram);
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
        readResponse(arr);
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
    std::array<char, max_length> buf;
    async_read(sd, buffer(buf, len), transfer_at_least(1), [&](error_code ec, size_t br) {
        if (!ec && br > 0) {
            QByteArray arr(buf.data(), br);
            readResponse(arr);
            readHeader(sd);
        }
    });
}
#endif

void NativeMessagingHost::readResponse(const QByteArray& arr)
{
    QJsonParseError err;
    QJsonDocument doc(QJsonDocument::fromJson(arr, &err));
    if (doc.isObject()) {
        QJsonObject json = doc.object();
        QString action = json.value("action").toString();
        if (!action.isEmpty()) {
            // Allow public keys to be changed without database being opened
            QMutexLocker locker(&m_mutex);
            if (action != "change-public-keys" && !m_service.isDatabaseOpened()) {
                if (!m_service.openDatabase()) {
                    sendErrorReply(action, ERROR_KEEPASS_DATABASE_NOT_OPENED);
                }
            } else {
                handleAction(json);
            }
        }
    }
}

void NativeMessagingHost::readLine()
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

void NativeMessagingHost::handleAction(const QJsonObject& json)
{
    QString action = json.value("action").toString();
    if (!action.isEmpty()) {
        if (action.compare("get-databasehash", Qt::CaseSensitive) == 0) {
            handleGetDatabaseHash(json, action);
        } else if (action.compare("change-public-keys", Qt::CaseSensitive) == 0) {
            handleChangePublicKeys(json, action);
        } else if (action.compare("associate", Qt::CaseSensitive) == 0) {
            handleAssociate(json, action);
        } else if (action.compare("test-associate", Qt::CaseSensitive) == 0) {
            handleTestAssociate(json, action);
        } else if (action.compare("get-logins", Qt::CaseSensitive) == 0) {
            handleGetLogins(json, action);
        } else if (action.compare("generate-password", Qt::CaseSensitive) == 0) {
            handleGeneratePassword(json, action);
        } else if (action.compare("set-login", Qt::CaseSensitive) == 0) {
            handleSetLogin(json, action);
        }
    }
}

void NativeMessagingHost::handleGetDatabaseHash(const QJsonObject& json, const QString& action)
{
    QString hash = getDataBaseHash();
    QString nonce = json.value("nonce").toString();
    QString encrypted = json.value("message").toString();

    QJsonObject decrypted = decryptMessage(encrypted, nonce, action);
    if (!decrypted.isEmpty()) {
        QString command = decrypted.value("action").toString();
        if (!hash.isEmpty() && command.compare("get-databasehash", Qt::CaseSensitive) == 0) {
            QJsonObject message;
            message["hash"] = hash;
            message["version"] = KEEPASSX_VERSION;

            QString replyMessage(QJsonDocument(message).toJson());
            QJsonObject response;
            response["action"] = action;
            response["message"] = encrypt(replyMessage, nonce);
            response["nonce"] = nonce;

            sendReply(response);
        } else {
            sendErrorReply(action, ERROR_KEEPASS_DATABASE_HASH_NOT_RECEIVED);
        }
    } else {
        sendErrorReply(action, ERROR_KEEPASS_CANNOT_DECRYPT_MESSAGE);
    }
}

void NativeMessagingHost::handleChangePublicKeys(const QJsonObject& json, const QString& action)
{
    QString nonce = json.value("nonce").toString();
    QString clientPublicKey = json.value("publicKey").toString();

    if (!clientPublicKey.isEmpty()) {
        QMutexLocker locker(&m_mutex);
        m_associated = false;
        unsigned char pk[crypto_box_PUBLICKEYBYTES];
        unsigned char sk[crypto_box_SECRETKEYBYTES];
        crypto_box_keypair(pk, sk);

        QString publicKey = getBase64FromKey(pk, crypto_box_PUBLICKEYBYTES);
        QString secretKey = getBase64FromKey(sk, crypto_box_SECRETKEYBYTES);
        m_clientPublicKey = clientPublicKey;
        m_publicKey = publicKey;
        m_secretKey = secretKey;

        QJsonObject response;
        response["action"] = action;
        response["publicKey"] = publicKey;
        response["nonce"] = nonce;
        response["version"] = KEEPASSX_VERSION;
        response["success"] = "true";

        sendReply(response);
    } else {
        sendErrorReply(action, ERROR_KEEPASS_CLIENT_PUBLIC_KEY_NOT_RECEIVED);
    }
}

void NativeMessagingHost::handleAssociate(const QJsonObject& json, const QString& action)
{
    QString hash = getDataBaseHash();
    QString nonce = json.value("nonce").toString();
    QString encrypted = json.value("message").toString();

    QMutexLocker locker(&m_mutex);
    QJsonObject decrypted = decryptMessage(encrypted, nonce, action);
    if (!decrypted.isEmpty()) {
        QString key = decrypted.value("key").toString();
        if (!key.isEmpty() && key.compare(m_clientPublicKey, Qt::CaseSensitive) == 0) {
            //qDebug("Keys match. Associate.");
            QString id = m_service.storeKey(key);
            if (id.isEmpty()) {
                sendErrorReply(action, ERROR_KEEPASS_ACTION_CANCELLED_OR_DENIED);
                return;
            }

            m_associated = true;

            // Encrypt a reply message
            QJsonObject message;
            message["hash"] = hash;
            message["version"] = KEEPASSX_VERSION;
            message["success"] = "true";
            message["id"] = id;
            message["nonce"] = nonce;

            QString replyMessage(QJsonDocument(message).toJson());
            QJsonObject response;
            response["action"] = action;
            response["message"] = encrypt(replyMessage, nonce);
            response["nonce"] = nonce;

            sendReply(response);
        }
    } else {
        sendErrorReply(action, ERROR_KEEPASS_ASSOCIATION_FAILED);
    }
}

void NativeMessagingHost::handleTestAssociate(const QJsonObject& json, const QString& action)
{
    QString hash = getDataBaseHash();
    QString nonce = json.value("nonce").toString();
    QString encrypted = json.value("message").toString();

    QJsonObject decrypted = decryptMessage(encrypted, nonce, action);
    if (!decrypted.isEmpty()) {
        QString responseKey = decrypted.value("key").toString();
        QString id = decrypted.value("id").toString();
        if (!id.isEmpty() && !responseKey.isEmpty()) {
            QMutexLocker locker(&m_mutex);
            QString key = m_service.getKey(id);
            if (key.isEmpty() || key != responseKey) {
                return;
            }

            m_associated = true;

            // Encrypt a reply message
            QJsonObject message;
            message["hash"] = hash;
            message["version"] = KEEPASSX_VERSION;
            message["success"] = "true";
            message["id"] = id;
            message["nonce"] = nonce;

            QString replyMessage(QJsonDocument(message).toJson());
            QJsonObject response;
            response["action"] = action;
            response["message"] = encrypt(replyMessage, nonce);
            response["nonce"] = nonce;

            sendReply(response);
        } else {
            sendErrorReply(action, ERROR_KEEPASS_DATABASE_NOT_OPENED);
        }
    } else {
        sendErrorReply(action, ERROR_KEEPASS_CANNOT_DECRYPT_MESSAGE);
    }
}

void NativeMessagingHost::handleGetLogins(const QJsonObject& json, const QString& action)
{
    QString hash = getDataBaseHash();
    QString nonce = json.value("nonce").toString();
    QString encrypted = json.value("message").toString();

    QMutexLocker locker(&m_mutex);
    if (!m_associated) {
        sendErrorReply(action, ERROR_KEEPASS_ASSOCIATION_FAILED);
    }

    QJsonObject decrypted = decryptMessage(encrypted, nonce, action);
    if (!decrypted.isEmpty()) {
        QJsonValue val = decrypted.value("url");
        if (val.isString()) {
            QString id = decrypted.value("id").toString();
            QString url = decrypted.value("url").toString();
            QString submit = decrypted.value("submitUrl").toString();
            QJsonArray users = m_service.findMatchingEntries(id, url, submit, "");

            if (users.count() <= 0) {
                return;
            } else {
                QJsonObject message;
                message["count"] = users.count();
                message["entries"] = users;
                message["hash"] = hash;
                message["version"] = KEEPASSX_VERSION;
                message["success"] = "true";
                message["id"] = id;
                message["nonce"] = nonce;

                QString replyMessage(QJsonDocument(message).toJson());
                QJsonObject response;
                response["action"] = action;
                response["message"] = encrypt(replyMessage, nonce);
                response["nonce"] = nonce;

                sendReply(response);
            }
        }
    } else {
        sendErrorReply(action, ERROR_KEEPASS_CANNOT_DECRYPT_MESSAGE);
    }
}

void NativeMessagingHost::handleGeneratePassword(const QJsonObject& json, const QString& action)
{
    QString nonce = json.value("nonce").toString();
    QString password = BrowserSettings::generatePassword();
    QString bits = QString::number(BrowserSettings::getbits()); // For some reason this always returns 1140 bits?

    QJsonArray arr;
    QJsonObject passwd;
    passwd["login"] = QString::number(password.length() * 8); //bits;
    passwd["password"] = password;
    arr.append(passwd);

    QJsonObject message;
    message["version"] = KEEPASSX_VERSION;
    message["success"] = "true";
    message["entries"] = arr;
    message["nonce"] = nonce;

    QString replyMessage(QJsonDocument(message).toJson());
    QJsonObject response;
    response["action"] = action;
    response["message"] = encrypt(replyMessage, nonce);
    response["nonce"] = nonce;

    sendReply(response);
}

void NativeMessagingHost::handleSetLogin(const QJsonObject& json, const QString& action)
{
    QString hash = getDataBaseHash();
    QString nonce = json.value("nonce").toString();
    QString encrypted = json.value("message").toString();

    QMutexLocker locker(&m_mutex);
    if (!m_associated) {
        sendErrorReply(action, ERROR_KEEPASS_ASSOCIATION_FAILED);
    }

    QJsonObject decrypted = decryptMessage(encrypted, nonce, action);
    if (!decrypted.isEmpty()) {
        QString url = decrypted.value("url").toString();
        if (url.isEmpty()) {
            return;
        } else {
            QString id = decrypted.value("id").toString();
            QString login = decrypted.value("login").toString();
            QString password = decrypted.value("password").toString();
            QString submitUrl = decrypted.value("submitUrl").toString();
            QString uuid = decrypted.value("uuid").toString();
            QString realm = ""; // ?

            if (uuid.isEmpty()) {
                m_service.addEntry(id, login, password, url, submitUrl, realm);
            } else {
                m_service.updateEntry(id, uuid, login, password, url);
            }

            QJsonObject message;
            message["count"] = QJsonValue::Null;
            message["entries"] = QJsonValue::Null;
            message["error"] = "";
            message["hash"] = hash;
            message["version"] = KEEPASSX_VERSION;
            message["success"] = "true";
            message["nonce"] = nonce;

            QString replyMessage(QJsonDocument(message).toJson());
            QJsonObject response;
            response["action"] = action;
            response["message"] = encrypt(replyMessage, nonce);
            response["nonce"] = nonce;

            sendReply(response);
        }
    } else {
        sendErrorReply(action, ERROR_KEEPASS_CANNOT_DECRYPT_MESSAGE);
    }
}

void NativeMessagingHost::sendReply(const QJsonObject json)
{
    QString reply(QJsonDocument(json).toJson(QJsonDocument::Compact));
    uint len = reply.length();
    std::cout << char(((len>>0) & 0xFF)) << char(((len>>8) & 0xFF)) << char(((len>>16) & 0xFF)) << char(((len>>24) & 0xFF));
    std::cout << reply.toStdString() << std::flush;

    if (BrowserSettings::supportBrowserProxy()) {
        m_udpSocket.writeDatagram(reply.toUtf8(), m_peerAddr, m_peerPort);
    }
}

void NativeMessagingHost::sendErrorReply(const QString& action, const int errorCode)
{
    QJsonObject response;
    response["action"] = action;
    response["errorCode"] = QString::number(errorCode);
    response["error"] = getErrorMessage(errorCode);
    sendReply(response);
}

QString NativeMessagingHost::getErrorMessage(const int errorCode) const
{
    switch (errorCode) {
        case ERROR_KEEPASS_DATABASE_NOT_OPENED:             return "Database not opened";
        case ERROR_KEEPASS_DATABASE_HASH_NOT_RECEIVED:      return "Database hash not available";
        case ERROR_KEEPASS_CLIENT_PUBLIC_KEY_NOT_RECEIVED:  return "Client public key not received";
        case ERROR_KEEPASS_CANNOT_DECRYPT_MESSAGE:          return "Cannot decrypt message";
        case ERROR_KEEPASS_TIMEOUT_OR_NOT_CONNECTED:        return "Timeout or cannot connect to KeePassXC";
        case ERROR_KEEPASS_ACTION_CANCELLED_OR_DENIED:      return "Action cancelled or denied";
        case ERROR_KEEPASS_CANNOT_ENCRYPT_MESSAGE:          return "Cannot encrypt message or public key not found. Is Native Messaging enabled in KeePassXC?";
        case ERROR_KEEPASS_ASSOCIATION_FAILED:              return "KeePassXC association failed, try again.";
        case ERROR_KEEPASS_KEY_CHANGE_FAILED:               return "Key change was not successful.";
        case ERROR_KEEPASS_ENCRYPTION_KEY_UNRECOGNIZED:     return "Encryption key is not recognized";
        case ERROR_KEEPASS_NO_SAVED_DATABASES_FOUND:        return "No saved databases found";
        default:                                            return "Unknown error";
    }
}

QString NativeMessagingHost::encrypt(const QString decrypted, const QString nonce)
{
    QString result;
    QMutexLocker locker(&m_mutex);
    const QByteArray ma = decrypted.toUtf8();
    const QByteArray na = base64Decode(nonce);
    const QByteArray ca = base64Decode(m_clientPublicKey);
    const QByteArray sa = base64Decode(m_secretKey);

    std::vector<unsigned char> m(ma.cbegin(), ma.cend());
    std::vector<unsigned char> n(na.cbegin(), na.cend());
    std::vector<unsigned char> ck(ca.cbegin(), ca.cend());
    std::vector<unsigned char> sk(sa.cbegin(), sa.cend());

    std::vector<unsigned char> e;
    e.resize(max_length);
    if (m.size() > 0 && n.size() > 0 && ck.size() > 0 && sk.size() > 0) {
        if (crypto_box_easy(e.data(), m.data(), m.size(), n.data(), ck.data(), sk.data()) == 0) {
           QByteArray res = getQByteArray(e.data(), (crypto_box_MACBYTES + ma.length()));
           result = res.toBase64();
        }
    }

    return result;
}

QByteArray NativeMessagingHost::decrypt(const QString encrypted, const QString nonce)
{
    QByteArray result;
    QMutexLocker locker(&m_mutex);
    const QByteArray ma = base64Decode(encrypted);
    const QByteArray na = base64Decode(nonce);
    const QByteArray ca = base64Decode(m_clientPublicKey);
    const QByteArray sa = base64Decode(m_secretKey);

    std::vector<unsigned char> m(ma.cbegin(), ma.cend());
    std::vector<unsigned char> n(na.cbegin(), na.cend());
    std::vector<unsigned char> ck(ca.cbegin(), ca.cend());
    std::vector<unsigned char> sk(sa.cbegin(), sa.cend());

    std::vector<unsigned char> d;
    d.resize(max_length);

    if (m.size() > 0 && n.size() > 0 && ck.size() > 0 && sk.size() > 0) {
        if (crypto_box_open_easy(d.data(), m.data(), ma.length(), n.data(), ck.data(), sk.data()) == 0) {
            result = getQByteArray(d.data(), strlen(reinterpret_cast<const char *>(d.data())));
        }
    }

    return result;
}

QJsonObject NativeMessagingHost::decryptMessage(const QString& message, const QString& nonce, const QString& action)
{
    QJsonObject json;
    if (message.length() > 0) {
        QByteArray ba = decrypt(message, nonce);
        if (ba.length() > 0) {
            json = getJSonObject(ba);
        } else {
            //qWarning("Cannot decrypt message");
            sendErrorReply(action, ERROR_KEEPASS_CANNOT_DECRYPT_MESSAGE);
        }
    } else {
        //qWarning("No message received");
    }
    return json;
}

QString NativeMessagingHost::getBase64FromKey(const uchar* array, const uint len)
{
    return getQByteArray(array, len).toBase64();
}

QByteArray NativeMessagingHost::getQByteArray(const uchar* array, const uint len)
{
    QByteArray qba;
    for (uint i = 0; i < len; i++) {
        qba.append(static_cast<char>(array[i]));
    }
    return qba;
}

QJsonObject NativeMessagingHost::getJSonObject(const uchar* pArray, const uint len)
{
    QByteArray arr = getQByteArray(pArray, len);
    QJsonParseError err;
    QJsonDocument doc(QJsonDocument::fromJson(arr, &err));

    if (!doc.isObject()) {
        //qWarning(err.errorString());
    }

    return doc.object();
}

QJsonObject NativeMessagingHost::getJSonObject(const QByteArray ba)
{
    QJsonParseError err;
    QJsonDocument doc(QJsonDocument::fromJson(ba, &err));

    if (!doc.isObject()) {
        //qWarning(err.errorString());
    }

    return doc.object();
}

QByteArray NativeMessagingHost::base64Decode(const QString str)
{
    return QByteArray::fromBase64(str.toUtf8());
}

QString NativeMessagingHost::getDataBaseHash()
{
    QMutexLocker locker(&m_mutex);
    QByteArray hash = QCryptographicHash::hash(
        (m_service.getDatabaseRootUuid() + m_service.getDatabaseRecycleBinUuid()).toUtf8(),
         QCryptographicHash::Sha256).toHex();
    return QString(hash);
}

void NativeMessagingHost::removeSharedEncryptionKeys()
{
    QMutexLocker locker(&m_mutex);
    m_service.removeSharedEncryptionKeys();
}

void NativeMessagingHost::removeStoredPermissions()
{
    QMutexLocker locker(&m_mutex);
    m_service.removeStoredPermissions();
}
