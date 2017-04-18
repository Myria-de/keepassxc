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
    void        Run();

private:
    void        HandleAction(const QJsonObject &json);
    void        Handle_GetDatabaseHash(const QString &valStr);
    void        HandleChangePublicKeys(const QJsonObject &json, const QString &valStr);
    void        HandleAssociate(const QJsonObject &json, const QString &valStr);
    void        HandleTestAssociate(const QJsonObject &json, const QString &valStr);
    void        HandleGetLogins(const QJsonObject &json, const QString &valStr);
    void        HandleGeneratePassword(const QJsonObject &json, const QString &valStr);
    void        HandleSetLogin(const QJsonObject &json, const QString &valStr);

    void        AppendText(const QString &str);
    void        SendReply(const QJsonObject json);

    QString     Encrypt(const QString decrypted, const QString nonce) const;
    QByteArray  Decrypt(const QString encrypted, const QString nonce) const;

signals:
    void        quit();

private slots:
    void        ReadLine();

private:
    static QString      getBase64FromKey(const uchar *array, const uint len);
    static QByteArray   getQByteArray(const uchar* array, const uint len);
    static QJsonObject  GetJSonObject(const uchar* pArray, const uint len);
    static QJsonObject  GetJSonObject(const QByteArray ba);
    static QByteArray   base64Decode(const QString str);

private:
     QSocketNotifier*   m_pNotifier;
     QString            m_ClientPublicKey;
     QString            m_PublicKey;
     QString            m_SecretKey;

     DatabaseTabWidget * const m_dbTabWidget;
};

#endif // CHROMELISTENER_H
