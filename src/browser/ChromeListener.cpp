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
#include "ChromeListener.h"
#include "BrowserSettings.h"
#include "config-keepassx.h"

#define MESSAGE_LENGTH  4096

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

ChromeListener::ChromeListener(DatabaseTabWidget* parent) : m_service(parent), m_sd(m_io_service, ::dup(STDIN_FILENO)), m_running(false), m_peerPort(0), m_localPort(19700)
{
    if (BrowserSettings::isEnabled() && !m_running) {
        run();
    }
}

ChromeListener::~ChromeListener()
{
    stop();
}

int ChromeListener::init()
{
    return sodium_init();
}

void ChromeListener::run()
{
    QMutexLocker locker(&m_mutex);
    if (!m_running) {
        if (init() == -1) {
            return;
        }

        m_running = true;
        m_fut = QtConcurrent::run(this, &ChromeListener::readLine);
    }

    if (BrowserSettings::supportBrowserProxy()) {
        m_localPort = BrowserSettings::udpPort();
        m_udpSocket.bind(QHostAddress::LocalHost, m_localPort, QUdpSocket::DontShareAddress);
        connect(&m_udpSocket, SIGNAL(readyRead()), this, SLOT(readDatagrams()));
    } else {
        m_udpSocket.close();
    }
}

void ChromeListener::stop()
{
    QMutexLocker locker(&m_mutex);
    m_udpSocket.close();

    if (m_sd.is_open()) {
        m_sd.cancel();
        m_sd.close();
    }

    if (!m_io_service.stopped()) {
        m_io_service.stop();
    }

    m_fut.waitForFinished();
    m_running = false;
}

void ChromeListener::readDatagrams()
{
    QByteArray dgram;

    while (m_udpSocket.hasPendingDatagrams()) {
        dgram.resize(m_udpSocket.pendingDatagramSize());
        m_udpSocket.readDatagram(dgram.data(), dgram.size(), &m_peerAddr, &m_peerPort);
    }

    readResponse(dgram);
}

void ChromeListener::readHeader(boost::asio::posix::stream_descriptor& sd)
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

void ChromeListener::readBody(boost::asio::posix::stream_descriptor& sd, const size_t len)
{
    std::array<char, MESSAGE_LENGTH> buf;
    async_read(sd, buffer(buf, len), transfer_at_least(1), [&](error_code ec, size_t br) {
        if (!ec && br > 0) {
            QByteArray arr(buf.data(), br);
            readResponse(arr);
            readHeader(sd);
        }
    });
}

void ChromeListener::readResponse(const QByteArray& arr)
{
    QJsonParseError err;
    QJsonDocument doc(QJsonDocument::fromJson(arr, &err));
    if (doc.isObject()) {
        QJsonObject json = doc.object();
        QString val = json.value("action").toString();
        if (!val.isEmpty()) {
            // Allow public keys to be changed without database being opened
            if (val != "change-public-keys" && !m_service.isDatabaseOpened()) {
                if (!m_service.openDatabase()) {
                    sendErrorReply(val, ERROR_KEEPASS_DATABASE_NOT_OPENED);
                }
            } else {
                handleAction(json);
            }
        }
    }
}

void ChromeListener::readLine()
{
    // Read the message header
    readHeader(m_sd);
    m_io_service.run();
}

void ChromeListener::handleAction(const QJsonObject& json)
{
    QString action = json.value("action").toString();
    if (!action.isEmpty()) {
        if (action == "get-databasehash") {
            handleGetDatabaseHash(json, action);
        } else if (action == "change-public-keys") {
            handleChangePublicKeys(json, action);
        } else if (action == "associate") {
            handleAssociate(json, action);
        } else if (action == "test-associate") {
            handleTestAssociate(json, action);
        } else if (action == "get-logins") {
            handleGetLogins(json, action);
        } else if (action == "generate-password") {
            handleGeneratePassword(json, action);
        } else if (action == "set-login") {
            handleSetLogin(json, action);
        }
    }
}

void ChromeListener::handleGetDatabaseHash(const QJsonObject& json, const QString& action)
{
    QString hash = getDataBaseHash();
    QString nonce = json.value("nonce").toString();
    QString encrypted = json.value("message").toString();

    QJsonObject decrypted = decryptMessage(encrypted, nonce, action);
    if (decrypted.isEmpty()) {
        return;
    } else {
        QJsonValue command = decrypted.value("action");
        if (!hash.isEmpty() && command.toString() == "get-databasehash") {
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
    }
}

QJsonObject ChromeListener::decryptMessage(const QString& message, const QString& nonce, const QString& action)
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

void ChromeListener::handleChangePublicKeys(const QJsonObject& json, const QString& action)
{
    QString nonce = json.value("nonce").toString();
    m_clientPublicKey = json.value("publicKey").toString();

    if (!m_clientPublicKey.isEmpty()) {
        unsigned char pk[crypto_box_PUBLICKEYBYTES];
        unsigned char sk[crypto_box_SECRETKEYBYTES];
        crypto_box_keypair(pk, sk);

        QString publicKey = getBase64FromKey(pk, crypto_box_PUBLICKEYBYTES);
        QString secretKey = getBase64FromKey(sk, crypto_box_SECRETKEYBYTES);
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

void ChromeListener::handleAssociate(const QJsonObject& json, const QString& action)
{
    QString hash = getDataBaseHash();
    QString nonce = json.value("nonce").toString();
    QString encrypted = json.value("message").toString();

    QJsonObject decrypted = decryptMessage(encrypted, nonce, action);
    if (decrypted.isEmpty()) {
        return;
    } else {
        QJsonValue key = decrypted.value("key");
        if (key.isString() && key.toString() == m_clientPublicKey) {
            //qDebug("Keys match. Associate.");
            QMutexLocker locker(&m_mutex);
            QString id = m_service.storeKey(key.toString());
            if (id.isEmpty()) {
                sendErrorReply(action, ERROR_KEEPASS_ACTION_CANCELLED_OR_DENIED);
                return;
            }

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
    }
}

void ChromeListener::handleTestAssociate(const QJsonObject& json, const QString& action)
{
    QString hash = getDataBaseHash();
    QString nonce = json.value("nonce").toString();
    QString encrypted = json.value("message").toString();

    QJsonObject decrypted = decryptMessage(encrypted, nonce, action);
    if (decrypted.isEmpty()) {
        return;
    } else {
        QString responseKey = decrypted.value("key").toString();
        QString id = decrypted.value("id").toString();
        if (!id.isEmpty() && !responseKey.isEmpty()) {
            QMutexLocker locker(&m_mutex);
            QString key = m_service.getKey(id);
            if (key.isEmpty() || key != responseKey) {
                return;
            }

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
    }
}

void ChromeListener::handleGetLogins(const QJsonObject& json, const QString& action)
{
    QString hash = getDataBaseHash();
    QString nonce = json.value("nonce").toString();
    QString encrypted = json.value("message").toString();

    QJsonObject decrypted = decryptMessage(encrypted, nonce, action);
    if (decrypted.isEmpty()) {
        return;
    } else {
        QJsonValue val = decrypted.value("url");
        if (val.isString()) {
            QString id = decrypted.value("id").toString();
            QString url = decrypted.value("url").toString();
            QString submit = decrypted.value("submitUrl").toString();
            QMutexLocker locker(&m_mutex);
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
    }
}

void ChromeListener::handleGeneratePassword(const QJsonObject& json, const QString& action)
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

void ChromeListener::handleSetLogin(const QJsonObject& json, const QString& action)
{
    QString hash = getDataBaseHash();
    QString nonce = json.value("nonce").toString();
    QString encrypted = json.value("message").toString();

    QJsonObject decrypted = decryptMessage(encrypted, nonce, action);
    if (decrypted.isEmpty()) {
        return;
    } else {
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
            QMutexLocker locker(&m_mutex);
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
    }
}

void ChromeListener::sendReply(const QJsonObject json)
{
    QString reply(QJsonDocument(json).toJson());
    uint len = reply.length();

    std::cout << char(((len>>0) & 0xFF))
                << char(((len>>8) & 0xFF))
                << char(((len>>16) & 0xFF))
                << char(((len>>24) & 0xFF));
    std::cout << reply.toStdString() << std::flush;

    if (BrowserSettings::supportBrowserProxy()) {
        m_udpSocket.writeDatagram(reply.toUtf8(), m_peerAddr, m_peerPort);
    }
}

void ChromeListener::sendErrorReply(const QString& action, const int errorCode)
{
    QJsonObject response;
    response["action"] = action;
    response["errorCode"] = QString::number(errorCode);
    response["error"] = getErrorMessage(errorCode);
    sendReply(response);
}

QString ChromeListener::getErrorMessage(const int errorCode) const
{
    switch (errorCode) {
        case ERROR_KEEPASS_DATABASE_NOT_OPENED:             return "Database not opened";
        case ERROR_KEEPASS_DATABASE_HASH_NOT_RECEIVED:      return "Database hash not available";
        case ERROR_KEEPASS_CLIENT_PUBLIC_KEY_NOT_RECEIVED:  return "Client public key not received";
        case ERROR_KEEPASS_CANNOT_DECRYPT_MESSAGE:          return "Cannot decrypt message";
        case ERROR_KEEPASS_TIMEOUT_OR_NOT_CONNECTED:        return "Timeout or cannot connect to KeePassXC";
        case ERROR_KEEPASS_ACTION_CANCELLED_OR_DENIED:      return "Action cancelled or denied";
        default:                                            return "Unknown error";
    }
}

QString ChromeListener::encrypt(const QString decrypted, const QString nonce) const
{
    QString result;
    const QByteArray ma = decrypted.toUtf8();
    const QByteArray na = base64Decode(nonce);
    const QByteArray ca = base64Decode(m_clientPublicKey);
    const QByteArray sa = base64Decode(m_secretKey);

    std::vector<unsigned char> m(ma.cbegin(), ma.cend());
    std::vector<unsigned char> n(na.cbegin(), na.cend());
    std::vector<unsigned char> ck(ca.cbegin(), ca.cend());
    std::vector<unsigned char> sk(sa.cbegin(), sa.cend());

    std::vector<unsigned char> e;
    e.resize(MESSAGE_LENGTH);

    if (crypto_box_easy(e.data(), m.data(), m.size(), n.data(), ck.data(), sk.data()) == 0) {
       QByteArray res = getQByteArray(e.data(), (crypto_box_MACBYTES + ma.length()));
       result = res.toBase64();
    }

    return result;
}

QByteArray ChromeListener::decrypt(const QString encrypted, const QString nonce) const
{
    QByteArray result;
    const QByteArray ma = base64Decode(encrypted);
    const QByteArray na = base64Decode(nonce);
    const QByteArray ca = base64Decode(m_clientPublicKey);
    const QByteArray sa = base64Decode(m_secretKey);

    std::vector<unsigned char> m(ma.cbegin(), ma.cend());
    std::vector<unsigned char> n(na.cbegin(), na.cend());
    std::vector<unsigned char> ck(ca.cbegin(), ca.cend());
    std::vector<unsigned char> sk(sa.cbegin(), sa.cend());

    std::vector<unsigned char> d;
    d.resize(MESSAGE_LENGTH);

    if (crypto_box_open_easy(d.data(), m.data(), ma.length(), n.data(), ck.data(), sk.data()) == 0) {
        result = getQByteArray(d.data(), strlen(reinterpret_cast<const char *>(d.data())));
    }

    return result;
}

QString ChromeListener::getBase64FromKey(const uchar* array, const uint len)
{
    return getQByteArray(array, len).toBase64();
}

QByteArray ChromeListener::getQByteArray(const uchar* array, const uint len)
{
    QByteArray qba;
    for (uint i = 0; i < len; i++) {
        qba.append(static_cast<char>(array[i]));
    }
    return qba;
}

QJsonObject ChromeListener::getJSonObject(const uchar* pArray, const uint len)
{
    QByteArray arr = getQByteArray(pArray, len);
    QJsonParseError err;
    QJsonDocument doc(QJsonDocument::fromJson(arr, &err));

    if (!doc.isObject()) {
        //qWarning(err.errorString());
    }

    return doc.object();
}

QJsonObject ChromeListener::getJSonObject(const QByteArray ba)
{
    QJsonParseError err;
    QJsonDocument doc(QJsonDocument::fromJson(ba, &err));

    if (!doc.isObject()) {
        //qWarning(err.errorString());
    }

    return doc.object();
}

QByteArray ChromeListener::base64Decode(const QString str)
{
    return QByteArray::fromBase64(str.toUtf8());
}

QString ChromeListener::getDataBaseHash()
{
    QMutexLocker locker(&m_mutex);
    QByteArray hash = QCryptographicHash::hash(
        (m_service.getDatabaseRootUuid() + m_service.getDatabaseRecycleBinUuid()).toUtf8(),
         QCryptographicHash::Sha256).toHex();
    return QString(hash);
}

void ChromeListener::removeSharedEncryptionKeys()
{
    QMutexLocker locker(&m_mutex);
    m_service.removeSharedEncryptionKeys();
}

void ChromeListener::removeStoredPermissions()
{
    QMutexLocker locker(&m_mutex);
    m_service.removeStoredPermissions();
}
