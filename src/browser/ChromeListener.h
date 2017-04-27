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

#ifndef CHROMELISTENER_H
#define CHROMELISTENER_H

#include <QObject>
#include <QSocketNotifier>
#include <QJsonObject>
#include <QJsonDocument>
#include "BrowserService.h"
#include "gui/DatabaseTabWidget.h"

#define ERROR_KEEPASS_DATABASE_NOT_OPENED   1

class ChromeListener : public QObject
{
    Q_OBJECT

public:
    explicit    ChromeListener(DatabaseTabWidget* parent = 0);
    void        run();

private:
    void        handleAction(const QJsonObject &json);
    void        handleGetDatabaseHash(const QString &valStr);
    void        handleChangePublicKeys(const QJsonObject &json, const QString &valStr);
    void        handleAssociate(const QJsonObject &json, const QString &valStr);
    void        handleTestAssociate(const QJsonObject &json, const QString &valStr);
    void        handleGetLogins(const QJsonObject &json, const QString &valStr);
    void        handleGeneratePassword(const QJsonObject &json, const QString &valStr);
    void        handleSetLogin(const QJsonObject &json, const QString &valStr);

    void        sendReply(const QJsonObject json);
    void        sendErrorReply(const QString &valStr, const int errorCode);

    QString     encrypt(const QString decrypted, const QString nonce) const;
    QByteArray  decrypt(const QString encrypted, const QString nonce) const;

    QString     getDataBaseHash();

    // Database functions
    bool        isDatabaseOpened() const;
    bool        openDatabase();
    QString     getDatabaseRootUuid();
    QString     getDatabaseRecycleBinUuid();
    Entry*      getConfigEntry(bool create);
    QString     storeKey(const QString &key);

signals:
    void        quit();

private slots:
    void        readLine();

private:
    static QString      getBase64FromKey(const uchar *array, const uint len);
    static QByteArray   getQByteArray(const uchar* array, const uint len);
    static QJsonObject  getJSonObject(const uchar* pArray, const uint len);
    static QJsonObject  getJSonObject(const QByteArray ba);
    static QByteArray   base64Decode(const QString str);

private:
     QSocketNotifier*   m_pNotifier;
     QString            m_clientPublicKey;
     QString            m_publicKey;
     QString            m_secretKey;

     //DatabaseTabWidget * const m_dbTabWidget;
     BrowserService     m_Service;
};

#endif // CHROMELISTENER_H
