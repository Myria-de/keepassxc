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

#ifndef BROWSERACTION_H
#define BROWSERACTION_H

#include <QObject>
#include <QJsonObject>
#include <QJsonDocument>
#include <QMutex>
#include "BrowserService.h"
#include "gui/DatabaseTabWidget.h"

#define MESSAGE_LENGTH  16*2014

class BrowserAction : public QObject
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
    explicit    BrowserAction(DatabaseTabWidget* parent = 0);
    ~BrowserAction();
    int                 init();
    QJsonObject         readResponse(const QByteArray& arr);
    QString             getErrorMessage(const int errorCode) const;
    void                removeSharedEncryptionKeys();
    void                removeStoredPermissions();

private:
    QJsonObject         handleAction(const QJsonObject& json);
    QJsonObject         handleGetDatabaseHash(const QJsonObject& json, const QString& action);
    QJsonObject         handleChangePublicKeys(const QJsonObject& json, const QString& action);
    QJsonObject         handleAssociate(const QJsonObject& json, const QString& action);
    QJsonObject         handleTestAssociate(const QJsonObject& json, const QString& action);
    QJsonObject         handleGetLogins(const QJsonObject& json, const QString& action);
    QJsonObject         handleGeneratePassword(const QJsonObject& json, const QString& action);
    QJsonObject         handleSetLogin(const QJsonObject& json, const QString& action);
    QJsonObject         getErrorReply(const QString& action, const int errorCode);
    QString             encrypt(const QString& decrypted, const QString& nonce);
    QByteArray          decrypt(const QString& encrypted, const QString& nonce);
    QJsonObject         decryptMessage(const QString& message, const QString& nonce, const QString& action = QString());
    QString             getDataBaseHash();

private:
    static QString      getBase64FromKey(const uchar* array, const uint len);
    static QByteArray   getQByteArray(const uchar* array, const uint len);
    static QJsonObject  getJSonObject(const uchar* pArray, const uint len);
    static QJsonObject  getJSonObject(const QByteArray ba);
    static QByteArray   base64Decode(const QString str);

private:
    QString             m_clientPublicKey;
    QString             m_publicKey;
    QString             m_secretKey;
    BrowserService      m_browserService;
    QMutex              m_mutex;
    bool                m_associated;
};

#endif // BROWSERACTION_H
