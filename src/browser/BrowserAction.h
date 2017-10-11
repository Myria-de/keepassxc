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

#include <QJsonObject>
#include <QMutex>
#include "BrowserService.h"

class BrowserAction
{
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
        ERROR_KEEPASS_NO_SAVED_DATABASES_FOUND = 11,
        ERROR_KEEPASS_INCORRECT_ACTION = 12,
        ERROR_KEEPASS_EMPTY_MESSAGE_RECEIVED = 13,
        ERROR_KEEPASS_NO_URL_PROVIDED = 14
    };

public:
    BrowserAction(DatabaseTabWidget* parent);
    ~BrowserAction();

    const QJsonObject   readResponse(const QJsonObject& json);

private:
    const QJsonObject   handleAction(const QJsonObject& json);
    const QJsonObject   handleChangePublicKeys(const QJsonObject& json, const QString& action);
    const QJsonObject   handleGetDatabaseHash(const QJsonObject& json, const QString& action);
    const QJsonObject   handleAssociate(const QJsonObject& json, const QString& action);
    const QJsonObject   handleTestAssociate(const QJsonObject& json, const QString& action);
    const QJsonObject   handleGetLogins(const QJsonObject& json, const QString& action);
    const QJsonObject   handleGeneratePassword(const QJsonObject& json, const QString& action);
    const QJsonObject   handleSetLogin(const QJsonObject& json, const QString& action);

    const QJsonObject   getErrorReply(const QString& action, const int errorCode) const;
    const QString       getErrorMessage(const int errorCode) const;
    const QString       getDataBaseHash();

    const QString       encryptMessage(const QJsonObject& message, const QString& nonce);
    const QJsonObject   decryptMessage(const QString& message, const QString& nonce, const QString& action = QString());
    const QString       encrypt(const QString decrypted, const QString nonce);
    const QByteArray    decrypt(const QString encrypted, const QString nonce);

    const QString       getBase64FromKey(const uchar* array, const uint len);
    const QByteArray    getQByteArray(const uchar* array, const uint len) const;
    const QJsonObject   getJSonObject(const uchar* pArray, const uint len) const;
    const QJsonObject   getJSonObject(const QByteArray ba) const;
    const QByteArray    base64Decode(const QString str);

public slots:
    void                removeSharedEncryptionKeys();
    void                removeStoredPermissions();

private:
    QMutex          m_mutex;
    BrowserService  m_browserService;
    QString         m_clientPublicKey;
    QString         m_publicKey;
    QString         m_secretKey;
    bool            m_associated;
};

#endif // BROWSERACTION_H
