/*
 *  Copyright (C) 2017 Sami Vänttinen <sami.vanttinen@gmail.com>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 2 or (at your option)
 *  version 3 of the License.
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
#include <iostream>
#include <cstring>
#include "sodium.h"
#include "crypto_box.h"
#include "randombytes.h"
#include "ChromeListener.h"
#include "BrowserSettings.h"
#include "config-keepassx.h"

#define MESSAGE_LENGTH  4096

ChromeListener::ChromeListener(DatabaseTabWidget* parent) : m_Service(parent)
{
    m_pNotifier = new QSocketNotifier(fileno(stdin), QSocketNotifier::Read, this);
    if (BrowserSettings::isEnabled())
        run();
}

void ChromeListener::run()
{
    connect(m_pNotifier, SIGNAL(activated(int)), this, SLOT(readLine()));
}

void ChromeListener::readLine()
{
    std::string line;
    uint length = 0;
    for (int i = 0; i < 4; i++) {
        uint read_char = getchar();
        length = length | (read_char << i*8);
    }

    std::string msg = "";
    QByteArray arr;
    for (uint i = 0; i < length; i++) {
        char c = getchar();
        msg += c;
        arr.append(c);
    }

    QString received(msg.c_str());
    //appendText("Received: " + received);

    // Replace this functionality with better one
    QJsonParseError err;
    QJsonDocument doc(QJsonDocument::fromJson(arr, &err));
    if (doc.isObject()) {
        QJsonObject json = doc.object();
        QJsonValue val = json.value("action");
        if (val.isString()) {
            if (!m_Service.isDatabaseOpened()) {
                if (!m_Service.openDatabase()) {
                    sendErrorReply(val.toString());
                    return;
                }
            }
            handleAction(json);
        }
    } else {
         //appendText("Not an object");
    }
}

void ChromeListener::handleAction(const QJsonObject &json)
{
    QJsonValue val = json.value("action");
    if (val.isString()) {
        QString valStr = val.toString();
        if (valStr == "get-databasehash")
            handleGetDatabaseHash(valStr);
        else if (valStr == "change-public-keys")
            handleChangePublicKeys(json, valStr);
        else if (valStr == "associate")
            handleAssociate(json, valStr);
        else if (valStr == "test-associate")
            handleTestAssociate(json, valStr);
        else if (valStr == "get-logins")
            handleGetLogins(json, valStr);
        else if (valStr == "generate-password")
            handleGeneratePassword(json, valStr);
        else if (valStr == "set-login")
            handleSetLogin(json, valStr);
        else if (valStr == "get-logins-count")
            handleGetLoginsCount(json, valStr);
    }
}

void ChromeListener::handleGetDatabaseHash(const QString &valStr)
{
    QString hash = getDataBaseHash();

    QJsonObject response;
    response["action"] = valStr;
    response["hash"] = hash;
    response["version"] = KEEPASSX_VERSION;

    sendReply(response);
}

void ChromeListener::handleChangePublicKeys(const QJsonObject &json, const QString &valStr)
{
    unsigned char pk[crypto_box_PUBLICKEYBYTES];
    unsigned char sk[crypto_box_SECRETKEYBYTES];
    crypto_box_keypair(pk, sk);

    QString publicKey = getBase64FromKey(pk, crypto_box_PUBLICKEYBYTES);
    QString secretKey = getBase64FromKey(sk, crypto_box_SECRETKEYBYTES);
    m_publicKey = publicKey;
    m_secretKey = secretKey;
    //appendText("Public key: " + publicKey + "Secret key: " + secretKey);

    QString nonce = json.value("nonce").toString();
    m_clientPublicKey = json.value("publicKey").toString();

    QJsonObject response;
    response["action"] = valStr;
    response["publicKey"] = publicKey;
    response["nonce"] = nonce;
    response["id"] = "testclient";
    response["success"] = "true";

    sendReply(response);
}

void ChromeListener::handleAssociate(const QJsonObject &json, const QString &valStr)
{
    QString hash = getDataBaseHash();
    QString nonce = json.value("nonce").toString();
    QString encrypted = json.value("message").toString();

    if (encrypted.length() > 0) {
        QByteArray ba = decrypt(encrypted, nonce);
        if (ba.length() > 0) {
            //appendText("Message decrypted: " + QString(ba));
            QJsonObject json = getJSonObject(ba);
            if (!json.isEmpty()) {
                QJsonValue val = json.value("key");
                if (val.isString() && val.toString() == m_clientPublicKey) {
                    //appendText("Keys match. Associate.");

                    QString id = m_Service.storeKey(val.toString());
                    if (id.isEmpty())
                        return;

                    // Encrypt a reply message
                    QJsonObject message;
                    message["hash"] = hash;
                    message["version"] = KEEPASSX_VERSION;
                    message["success"] = "true";
                    message["id"] = id;
                    message["nonce"] = nonce;

                    QString replyMessage(QJsonDocument(message).toJson());
                    QJsonObject response;
                    response["action"] = valStr;
                    response["message"] = encrypt(replyMessage, nonce);
                    response["nonce"] = nonce;

                    sendReply(response);
                }
            }
        } else {
            //appendText("Cannot decrypt message");
        }
    } else {
        //appendText("No message received");
    }
}

void ChromeListener::handleTestAssociate(const QJsonObject &json, const QString &valStr)
{
    QString hash = getDataBaseHash();
    QString nonce = json.value("nonce").toString();
    QString encrypted = json.value("message").toString();

    if (encrypted.length() > 0) {
        QByteArray ba = decrypt(encrypted, nonce);
        if (ba.length() > 0) {
            //appendText("Message decrypted: " + QString(ba));
            QJsonObject json = getJSonObject(ba);
            if (!json.isEmpty()) {
                QJsonValue val = json.value("id");
                QString id = val.toString();
                if (!id.isEmpty())
                {
                    QString key = m_Service.getKey(id);
                    if (key.isEmpty())
                        return;

                    // Encrypt a reply message
                    QJsonObject message;
                    message["hash"] = hash;
                    message["version"] = KEEPASSX_VERSION;
                    message["success"] = "true";
                    message["id"] = id;
                    message["nonce"] = nonce;

                    QString replyMessage(QJsonDocument(message).toJson());
                    QJsonObject response;
                    response["action"] = valStr;
                    response["message"] = encrypt(replyMessage, nonce);
                    response["nonce"] = nonce;

                    sendReply(response);
                }
            }
        } else {
            //appendText("Cannot decrypt message");
        }
    } else {
        //appendText("No message received");
    }
}

void ChromeListener::handleGetLogins(const QJsonObject &json, const QString &valStr)
{
    QString hash = getDataBaseHash();
    QString nonce = json.value("nonce").toString();
    QString encrypted = json.value("message").toString();

    if (encrypted.length() > 0) {
        QByteArray ba = decrypt(encrypted, nonce);
        if (ba.length() > 0) {
            //appendText("Message decrypted: " + QString(ba));
            QJsonObject json = getJSonObject(ba);
            if (!json.isEmpty()) {
                QJsonValue val = json.value("url");
                if (val.isString()) {
                    //appendText("URL: " + val.toString());

                    QJsonValue idVal = json.value("id");
                    QJsonValue urlVal = json.value("url");
                    QJsonValue submitVal = json.value("submitUrl");
                    QJsonArray users = m_Service.findMatchingEntries(idVal.toString(), urlVal.toString(), submitVal.toString(), "");

                    QJsonObject message;
                    message["count"] = users.count();
                    message["entries"] = users;
                    message["hash"] = hash;
                    message["version"] = KEEPASSX_VERSION;
                    message["success"] = "true";
                    message["id"] = "testclient";
                    message["nonce"] = nonce;

                    QString replyMessage(QJsonDocument(message).toJson());
                    QJsonObject response;
                    response["action"] = valStr;
                    response["message"] = encrypt(replyMessage, nonce);
                    response["nonce"] = nonce;

                    sendReply(response);
                }
            }
        } else {
            //appendText("Cannot decrypt message");
        }
    } else {
        //appendText("No message received");
    }
}

void ChromeListener::handleGeneratePassword(const QJsonObject &json, const QString &valStr)
{
    QString nonce = json.value("nonce").toString();
    QString password = BrowserSettings::generatePassword();
    QString bits = QString::number(BrowserSettings::getbits());

    QJsonArray arr;
    QJsonObject passwd;
    passwd["login"] = bits;
    passwd["password"] = password;
    arr.append(passwd);

    QJsonObject message;
    message["version"] = KEEPASSX_VERSION;
    message["success"] = "true";
    message["entries"] = arr;
    message["nonce"] = nonce;

    QString replyMessage(QJsonDocument(message).toJson());
    QJsonObject response;
    response["action"] = valStr;
    response["message"] = encrypt(replyMessage, nonce);
    response["nonce"] = nonce;

    sendReply(response);
}

void ChromeListener::handleSetLogin(const QJsonObject &json, const QString &valStr)
{
    QString hash = getDataBaseHash();
    QString nonce = json.value("nonce").toString();
    QString encrypted = json.value("message").toString();

    if (encrypted.length() > 0) {
        QByteArray ba = decrypt(encrypted, nonce);
        if (ba.length() > 0) {
            //appendText("Message decrypted: " + QString(ba));
            QJsonObject json = getJSonObject(ba);
            if (!json.isEmpty()) {
                QString url = json.value("url").toString();
                if (!url.isEmpty()) {
                    //appendText("URL: " + url);

                    QString id = json.value("id").toString();
                    QString login = json.value("login").toString();
                    QString password = json.value("password").toString();
                    QString submitUrl = json.value("submitUrl").toString();
                    QString uuid = json.value("uuid").toString();
                    QString realm = ""; // ?
                     if (uuid.isEmpty())
                        m_Service.addEntry(id, login, password, url, submitUrl, realm);
                    else
                        m_Service.updateEntry(id, uuid, login, password, url);

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
                    response["action"] = valStr;
                    response["message"] = encrypt(replyMessage, nonce);
                    response["nonce"] = nonce;

                    sendReply(response);
                }
            }
        } else {
            //appendText("Cannot decrypt message");
        }
    } else {
        //appendText("No message received");
    }
}

void ChromeListener::handleGetLoginsCount(const QJsonObject &json, const QString &valStr)
{

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

    //appendText(reply);
}

void ChromeListener::sendErrorReply(const QString &valStr/*const int errCode*/)
{
    QJsonObject response;
    response["action"] = valStr;
    response["error"] = "error";    // errorCode
    sendReply(response);
}

QString ChromeListener::encrypt(const QString decrypted, const QString nonce) const
{
    QString result;
    unsigned char n[crypto_box_NONCEBYTES];
    unsigned char ck[crypto_box_PUBLICKEYBYTES];
    unsigned char sk[crypto_box_SECRETKEYBYTES];
    unsigned char m[MESSAGE_LENGTH] = {0};
    unsigned char e[MESSAGE_LENGTH] = {0};

    const QByteArray ma = decrypted.toUtf8();
    const QByteArray na = base64Decode(nonce);
    const QByteArray ca = base64Decode(m_clientPublicKey);
    const QByteArray sa = base64Decode(m_secretKey);

    std::memcpy(m, ma.toStdString().data(), ma.length());
    std::memcpy(n, na.toStdString().data(), na.length());
    std::memcpy(ck, ca.toStdString().data(), ca.length());
    std::memcpy(sk, sa.toStdString().data(), sa.length());

    if (crypto_box_easy(e, m, ma.length(), n, ck, sk) == 0) {
        QByteArray res = getQByteArray(e, (crypto_box_MACBYTES + ma.length()));
        result = res.toBase64();
    }

    return result;
}

QByteArray ChromeListener::decrypt(const QString encrypted, const QString nonce) const
{
    QByteArray result;
    unsigned char n[crypto_box_NONCEBYTES];
    unsigned char ck[crypto_box_PUBLICKEYBYTES];
    unsigned char sk[crypto_box_SECRETKEYBYTES];
    unsigned char m[MESSAGE_LENGTH] = {0};
    unsigned char d[MESSAGE_LENGTH] = {0};

    const QByteArray ma = base64Decode(encrypted);
    const QByteArray na = base64Decode(nonce);
    const QByteArray ca = base64Decode(m_clientPublicKey);
    const QByteArray sa = base64Decode(m_secretKey);

    std::memcpy(m, ma.toStdString().data(), ma.length());
    std::memcpy(n, na.toStdString().data(), na.length());
    std::memcpy(ck, ca.toStdString().data(), ca.length());
    std::memcpy(sk, sa.toStdString().data(), sa.length());

    if (crypto_box_open_easy(d, m, ma.length(), n, ck, sk) == 0) {
        result = getQByteArray(d, strlen(reinterpret_cast<const char *>(d)));
    }

    return result;
}

QString ChromeListener::getBase64FromKey(const uchar *array, const uint len)
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
        //appendText(err.errorString());
    }

    return doc.object();
}

QJsonObject ChromeListener::getJSonObject(const QByteArray ba)
{
    QJsonParseError err;
    QJsonDocument doc(QJsonDocument::fromJson(ba, &err));

    if (!doc.isObject()) {
        //appendText(err.errorString());
    }

    return doc.object();
}

QByteArray ChromeListener::base64Decode(const QString str)
{
    return QByteArray::fromBase64(str.toUtf8());
}

QString ChromeListener::getDataBaseHash()
{
    QByteArray hash = QCryptographicHash::hash(
        (m_Service.getDatabaseRootUuid() + m_Service.getDatabaseRecycleBinUuid()).toUtf8(),
         QCryptographicHash::Sha256).toHex();
    return QString(hash);
}
