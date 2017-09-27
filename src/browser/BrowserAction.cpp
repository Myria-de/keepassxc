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
#include "sodium.h"
#include "sodium/crypto_box.h"
#include "sodium/randombytes.h"
#include "BrowserAction.h"
#include "BrowserSettings.h"
#include "config-keepassx.h"

BrowserAction::BrowserAction(DatabaseTabWidget* parent) :
    m_browserService(parent),
    m_mutex(QMutex::Recursive),
    m_associated(false)
{

}

BrowserAction::~BrowserAction()
{

}

int BrowserAction::init()
{
    return sodium_init();
}

QJsonObject BrowserAction::readResponse(const QByteArray& arr)
{
    QJsonParseError err;
    QJsonDocument doc(QJsonDocument::fromJson(arr, &err));
    if (doc.isObject()) {
        QJsonObject json = doc.object();
        QString action = json.value("action").toString();
        if (!action.isEmpty()) {
            // Allow public keys to be changed without database being opened
            QMutexLocker locker(&m_mutex);
            if (action != "change-public-keys" && !m_browserService.isDatabaseOpened()) {
                if (!m_browserService.openDatabase()) {
                    return getErrorReply(action, ERROR_KEEPASS_DATABASE_NOT_OPENED);
                }
            } else {
                return handleAction(json);
            }
        }
    }
    return QJsonObject();
}

QString BrowserAction::getErrorMessage(const int errorCode) const
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

void BrowserAction::removeSharedEncryptionKeys()
{
    QMutexLocker locker(&m_mutex);
    m_browserService.removeSharedEncryptionKeys();
}

void BrowserAction::removeStoredPermissions()
{
    QMutexLocker locker(&m_mutex);
    m_browserService.removeStoredPermissions();
}

QJsonObject BrowserAction::handleAction(const QJsonObject& json)
{
    QString action = json.value("action").toString();
    if (!action.isEmpty()) {
        if (action.compare("get-databasehash", Qt::CaseSensitive) == 0) {
            return handleGetDatabaseHash(json, action);
        } else if (action.compare("change-public-keys", Qt::CaseSensitive) == 0) {
            return handleChangePublicKeys(json, action);
        } else if (action.compare("associate", Qt::CaseSensitive) == 0) {
            return handleAssociate(json, action);
        } else if (action.compare("test-associate", Qt::CaseSensitive) == 0) {
            return handleTestAssociate(json, action);
        } else if (action.compare("get-logins", Qt::CaseSensitive) == 0) {
            return handleGetLogins(json, action);
        } else if (action.compare("generate-password", Qt::CaseSensitive) == 0) {
            return handleGeneratePassword(json, action);
        } else if (action.compare("set-login", Qt::CaseSensitive) == 0) {
            return handleSetLogin(json, action);
        }
    }
    return QJsonObject();
}

QJsonObject BrowserAction::handleGetDatabaseHash(const QJsonObject& json, const QString& action)
{
    QString hash = getDataBaseHash();
    QString nonce = json.value("nonce").toString();
    QString encrypted = json.value("message").toString();

    QJsonObject decrypted = decryptMessage(encrypted, nonce, action);
    if (!decrypted.isEmpty()) {
        QString command =  decrypted.value("action").toString();
        if (!hash.isEmpty() && command.compare("get-databasehash", Qt::CaseSensitive) == 0) {
            QJsonObject message;
            message["hash"] = hash;
            message["version"] = KEEPASSX_VERSION;

            QString replyMessage(QJsonDocument(message).toJson());
            QJsonObject response;
            response["action"] = action;
            response["message"] = encrypt(replyMessage, nonce);
            response["nonce"] = nonce;

            return response;
        } else {
            return getErrorReply(action, ERROR_KEEPASS_DATABASE_HASH_NOT_RECEIVED);
        }
    }

    return getErrorReply(action, ERROR_KEEPASS_CANNOT_DECRYPT_MESSAGE);
}

QJsonObject BrowserAction::handleChangePublicKeys(const QJsonObject& json, const QString& action)
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
        m_publicKey = publicKey;
        m_secretKey = secretKey;
        m_clientPublicKey = clientPublicKey;

        QJsonObject response;
        response["action"] = action;
        response["publicKey"] = publicKey;
        response["nonce"] = nonce;
        response["version"] = KEEPASSX_VERSION;
        response["success"] = "true";

        return response;
    }

    return getErrorReply(action, ERROR_KEEPASS_CLIENT_PUBLIC_KEY_NOT_RECEIVED);
}

QJsonObject BrowserAction::handleAssociate(const QJsonObject& json, const QString& action)
{
    QString hash = getDataBaseHash();
    QString nonce = json.value("nonce").toString();
    QString encrypted = json.value("message").toString();

    QJsonObject decrypted = decryptMessage(encrypted, nonce, action);
    if (!decrypted.isEmpty()) {
        QString key = decrypted.value("key").toString();
        if (!key.isEmpty() && key.compare(m_clientPublicKey, Qt::CaseSensitive) == 0) {
            // Keys match, associate
            QMutexLocker locker(&m_mutex);
            QString id = m_browserService.storeKey(key);

            if (id.isEmpty()) {
                return getErrorReply(action, ERROR_KEEPASS_ACTION_CANCELLED_OR_DENIED);
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

            return response;
        } else {
            return getErrorReply(action, ERROR_KEEPASS_ASSOCIATION_FAILED);
        }
    }

    return getErrorReply(action, ERROR_KEEPASS_CANNOT_DECRYPT_MESSAGE);
}

QJsonObject BrowserAction::handleTestAssociate(const QJsonObject& json, const QString& action)
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
            QString key = m_browserService.getKey(id);

            if (key.isEmpty() || key != responseKey) {
                return QJsonObject();
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

            return response;
        } else {
            return getErrorReply(action, ERROR_KEEPASS_DATABASE_NOT_OPENED);
        }
    }

    return getErrorReply(action, ERROR_KEEPASS_CANNOT_DECRYPT_MESSAGE);
}

QJsonObject BrowserAction::handleGetLogins(const QJsonObject& json, const QString& action)
{
    QString hash = getDataBaseHash();
    QString nonce = json.value("nonce").toString();
    QString encrypted = json.value("message").toString();

    if (!m_associated) {
        return getErrorReply(action, ERROR_KEEPASS_ASSOCIATION_FAILED);
    }

    QJsonObject decrypted = decryptMessage(encrypted, nonce, action);
    if (!decrypted.isEmpty()) {
        QJsonValue val = decrypted.value("url");
        if (val.isString()) {
            QString id = decrypted.value("id").toString();
            QString url = decrypted.value("url").toString();
            QString submit = decrypted.value("submitUrl").toString();
            QMutexLocker locker(&m_mutex);
            QJsonArray users = m_browserService.findMatchingEntries(id, url, submit, "");

            if (users.count() <= 0) {
                return QJsonObject();   // Empty response. Not an actual error you want to display
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

                return response;
            }
        }
    }

    return getErrorReply(action, ERROR_KEEPASS_CANNOT_DECRYPT_MESSAGE);
}

QJsonObject BrowserAction::handleGeneratePassword(const QJsonObject& json, const QString& action)
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

    return response;
}

QJsonObject BrowserAction::handleSetLogin(const QJsonObject& json, const QString& action)
{
    QString hash = getDataBaseHash();
    QString nonce = json.value("nonce").toString();
    QString encrypted = json.value("message").toString();

    if (!m_associated) {
        return getErrorReply(action, ERROR_KEEPASS_ASSOCIATION_FAILED);
    }

    QJsonObject decrypted = decryptMessage(encrypted, nonce, action);
    if (!decrypted.isEmpty()) {
        QString url = decrypted.value("url").toString();
        if (url.isEmpty()) {
            return QJsonObject();   // Empty response. Not an actual error you want to display
        } else {
            QString id = decrypted.value("id").toString();
            QString login = decrypted.value("login").toString();
            QString password = decrypted.value("password").toString();
            QString submitUrl = decrypted.value("submitUrl").toString();
            QString uuid = decrypted.value("uuid").toString();
            QString realm = "";
            QMutexLocker locker(&m_mutex);

            if (uuid.isEmpty()) {
                m_browserService.addEntry(id, login, password, url, submitUrl, realm);
            } else {
                m_browserService.updateEntry(id, uuid, login, password, url);
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

            return response;
        }
    }

    return getErrorReply(action, ERROR_KEEPASS_CANNOT_DECRYPT_MESSAGE);
}

QJsonObject BrowserAction::getErrorReply(const QString& action, const int errorCode)
{
    QJsonObject response;
    response["action"] = action;
    response["errorCode"] = QString::number(errorCode);
    response["error"] = getErrorMessage(errorCode);
    return response;
}

QString BrowserAction::encrypt(const QString& decrypted, const QString& nonce)
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
    e.resize(MESSAGE_LENGTH);

    if (m.size() > 0 && n.size() > 0 && ck.size() > 0 && sk.size() > 0) {
        if (crypto_box_easy(e.data(), m.data(), m.size(), n.data(), ck.data(), sk.data()) == 0) {
           QByteArray res = getQByteArray(e.data(), (crypto_box_MACBYTES + ma.length()));
           result = res.toBase64();
        }
    }

    return result;
}

QByteArray BrowserAction::decrypt(const QString& encrypted, const QString& nonce)
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
    d.resize(MESSAGE_LENGTH);

    if (m.size() > 0 && n.size() > 0 && ck.size() > 0 && sk.size() > 0) {
        if (crypto_box_open_easy(d.data(), m.data(), ma.length(), n.data(), ck.data(), sk.data()) == 0) {
            std::string response(d.begin(), d.end());
            result = QByteArray(response.c_str(), response.length());
        }
    }

    return result;
}

QJsonObject BrowserAction::decryptMessage(const QString& message, const QString& nonce, const QString& action)
{
    QJsonObject json;
    if (message.length() > 0) {
        QByteArray ba = decrypt(message, nonce);
        if (ba.length() > 0) {
            json = getJSonObject(ba);
        } else {
            //qWarning("Cannot decrypt message");
            return getErrorReply(action, ERROR_KEEPASS_CANNOT_DECRYPT_MESSAGE);
        }
    } else {
        //qWarning("No message received");
    }
    return json;
}

QString BrowserAction::getBase64FromKey(const uchar* array, const uint len)
{
    return getQByteArray(array, len).toBase64();
}

QByteArray BrowserAction::getQByteArray(const uchar* array, const uint len)
{
    QByteArray qba;
    for (uint i = 0; i < len; i++) {
        qba.append(static_cast<char>(array[i]));
    }
    return qba;
}

QJsonObject BrowserAction::getJSonObject(const uchar* pArray, const uint len)
{
    QByteArray arr = getQByteArray(pArray, len);
    QJsonParseError err;
    QJsonDocument doc(QJsonDocument::fromJson(arr, &err));

    if (!doc.isObject()) {
        //qWarning(err.errorString());
    }

    return doc.object();
}

QJsonObject BrowserAction::getJSonObject(const QByteArray ba)
{
    QJsonParseError err;
    QJsonDocument doc(QJsonDocument::fromJson(ba, &err));

    if (!doc.isObject()) {
        //qWarning(err.errorString());
    }

    return doc.object();
}

QByteArray BrowserAction::base64Decode(const QString str)
{
    return QByteArray::fromBase64(str.toUtf8());
}

QString BrowserAction::getDataBaseHash()
{
    QMutexLocker locker(&m_mutex);
    QString rootUuid = m_browserService.getDatabaseRootUuid();
    QString recycleBinUuid = m_browserService.getDatabaseRecycleBinUuid();
    QByteArray hash = QCryptographicHash::hash((rootUuid + recycleBinUuid).toUtf8(), QCryptographicHash::Sha256).toHex();
    return QString(hash);
}
