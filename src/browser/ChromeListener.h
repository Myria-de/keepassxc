#ifndef CHROMELISTENER_H
#define CHROMELISTENER_H

#include <QObject>
#include <QSocketNotifier>
#include <QJsonObject>
#include <QJsonDocument>
#include "gui/DatabaseTabWidget.h"

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

    void        appendText(const QString &str);
    void        sendReply(const QJsonObject json);
    void        sendErrorReply(const QString &valStr/*const int errCode*/);

    QString     encrypt(const QString decrypted, const QString nonce) const;
    QByteArray  decrypt(const QString encrypted, const QString nonce) const;

    bool        isDatabaseOpened() const;
    bool        openDatabase();

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

     DatabaseTabWidget * const m_dbTabWidget;
};

#endif // CHROMELISTENER_H
