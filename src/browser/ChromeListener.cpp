#include <QJsonArray>
#include <iostream>
#include <cstring>
#include "sodium.h"
#include "crypto_box.h"
#include "randombytes.h"
#include "ChromeListener.h"
#include "BrowserSettings.h"

#define MESSAGE_LENGTH  4096

ChromeListener::ChromeListener(DatabaseTabWidget* parent) : m_dbTabWidget(parent)
{
    m_pNotifier = new QSocketNotifier(fileno(stdin), QSocketNotifier::Read, this);
}

void ChromeListener::Run()
{
    connect(m_pNotifier, SIGNAL(activated(int)), this, SLOT(ReadLine()));
}

void ChromeListener::ReadLine()
{
    std::string line;
    uint length = 0;
    for (int i = 0; i < 4; i++)
    {
        uint read_char = getchar();
        length = length | (read_char << i*8);
    }

    std::string msg = "";
    QByteArray arr;
    for (uint i = 0; i < length; i++)
    {
        char c = getchar();
        msg += c;
        arr.append(c);
    }

    QString received(msg.c_str());
    AppendText("Received: " + received);

    // Replace this functionality
    QJsonParseError err;
    QJsonDocument doc(QJsonDocument::fromJson(arr, &err));
    if (doc.isObject())
    {
        QJsonObject json = doc.object();
        QJsonValue val = json.value("action");
        if (val.isString())
        {
            HandleAction(json);
        }
    }
    else {
         AppendText("Not an object");
    }
}

void ChromeListener::HandleAction(const QJsonObject &json)
{
    QJsonValue val = json.value("action");
    if (val.isString())
    {
        QString valStr = val.toString();
        if (valStr == "get-databasehash")
        {
            Handle_GetDatabaseHash(valStr);
        }
        else if (valStr == "change-public-keys")
        {
            HandleChangePublicKeys(json, valStr);
        }
        else if (valStr == "associate")
        {
            HandleAssociate(json, valStr);
        }
        else if (valStr == "test-associate")
        {
            HandleTestAssociate(json, valStr);
        }
        else if (valStr == "get-logins")
        {
            HandleGetLogins(json, valStr);
        }
        else if (valStr == "generate-password")
        {
            HandleGeneratePassword(json, valStr);
        }
        else if (valStr == "set-login")
        {
            HandleSetLogin(json, valStr);
        }
    }
}

void ChromeListener::Handle_GetDatabaseHash(const QString &valStr)
{
    AppendText("Sending database hash..");

    QJsonObject response;
    response["action"] = valStr;
    response["hash"] = "29234e32274a32276e25666a42";
    response["version"] = "2.1.2";

    SendReply(response);
}

void ChromeListener::HandleChangePublicKeys(const QJsonObject &json, const QString &valStr)
{
    unsigned char pk[crypto_box_PUBLICKEYBYTES];
    unsigned char sk[crypto_box_SECRETKEYBYTES];
    crypto_box_keypair(pk, sk);

    QString publicKey = getBase64FromKey(pk, crypto_box_PUBLICKEYBYTES);
    QString secretKey = getBase64FromKey(sk, crypto_box_SECRETKEYBYTES);
    m_PublicKey = publicKey;
    m_SecretKey = secretKey;
    AppendText("Public key: " + publicKey + "Secret key: " + secretKey);

    QString nonce = json.value("nonce").toString();
    m_ClientPublicKey = json.value("publicKey").toString();

    QJsonObject response;
    response["action"] = valStr;
    response["publicKey"] = publicKey;
    response["nonce"] = nonce;
    response["id"] = "testclient";
    response["success"] = "true";

    SendReply(response);
}

void ChromeListener::HandleAssociate(const QJsonObject &json, const QString &valStr)
{
    QString nonce = json.value("nonce").toString();
    QString encrypted = json.value("message").toString();
    if (encrypted.length() > 0)
    {
        QByteArray ba = Decrypt(encrypted, nonce);
        if (ba.length() > 0)
        {
            AppendText("Message decrypted: " + QString(ba));
            QJsonObject json = GetJSonObject(ba);
            if (!json.isEmpty())
            {
                QJsonValue val = json.value("key");
                if (val.isString() && val.toString() == m_ClientPublicKey)
                {
                    AppendText("Keys match. Associate.");

                    // Encrypt a reply message
                    QJsonObject message;
                    message["hash"] = "29234e32274a32276e25666a42";
                    message["version"] = "2.1.2";
                    message["success"] = "true";
                    message["id"] = "testclient";
                    message["nonce"] = nonce;

                    QString replyMessage(QJsonDocument(message).toJson());
                    QJsonObject response;
                    response["action"] = valStr;
                    response["message"] = Encrypt(replyMessage, nonce);
                    response["nonce"] = nonce;

                    SendReply(response);
                }
            }
        }
        else
        {
            AppendText("Cannot decrypt message");
        }
    }
    else
    {
        AppendText("No message received");
    }
}

void ChromeListener::HandleTestAssociate(const QJsonObject &json, const QString &valStr)
{
    // { "action": "test-associate", "version": "2.1.2", "nonce": "tZvLrBzkQ9GxXq9PvKJj4iAnfPT0VZ3Q", "hash": "29234e32274a32276e25666a42", "id": "testclient", "success": "true" }
    QString nonce = json.value("nonce").toString();
    QString encrypted = json.value("message").toString();
    if (encrypted.length() > 0)
    {
        QByteArray ba = Decrypt(encrypted, nonce);
        if (ba.length() > 0)
        {
            AppendText("Message decrypted: " + QString(ba));
            QJsonObject json = GetJSonObject(ba);
            if (!json.isEmpty())
            {
                QJsonValue val = json.value("key");
                //if (val.isString() && val.toString() == m_ClientPublicKey)  // This should be compared to the key received with 'associate'
                {
                    AppendText("Keys match. Associate.");

                    // Encrypt a reply message
                    QJsonObject message;
                    message["hash"] = "29234e32274a32276e25666a42";
                    message["version"] = "2.1.2";
                    message["success"] = "true";
                    message["id"] = "testclient";
                    message["nonce"] = nonce;

                    QString replyMessage(QJsonDocument(message).toJson());
                    QJsonObject response;
                    response["action"] = valStr;
                    response["message"] = Encrypt(replyMessage, nonce);
                    response["nonce"] = nonce;

                    SendReply(response);
                }
            }
        }
        else
        {
            AppendText("Cannot decrypt message");
        }
    }
    else
    {
        AppendText("No message received");
    }
}

void ChromeListener::HandleGetLogins(const QJsonObject &json, const QString &valStr)
{
    // { "action": "get-logins", "count": "2", "entries" : [{"login": "user1", "name": "user1", "password": "passwd1"}, {"login": "user2", "name": "user2", "password": "passwd2"}],
    // "nonce": "tZvLrBzkQ9GxXq9PvKJj4iAnfPT0VZ3Q", "success": "true", "hash": "29234e32274a32276e25666a42", "version": "2.1.2" }
    QString nonce = json.value("nonce").toString();
    QString encrypted = json.value("message").toString();
    if (encrypted.length() > 0)
    {
        QByteArray ba = Decrypt(encrypted, nonce);
        if (ba.length() > 0)
        {
            AppendText("Message decrypted: " + QString(ba));
            QJsonObject json = GetJSonObject(ba);
            if (!json.isEmpty())
            {
                QJsonValue val = json.value("url");
                if (val.isString())
                {
                    AppendText("URL: " + val.toString());

                    int userCount = 2;
                    QJsonArray users;

                    for (int i = 0; i < userCount; i++)
                    {
                        QJsonObject user;
                        user["login"] = "user" + QString::number(i);
                        user["name"] = "user" + QString::number(i);
                        user["password"] = "passwd" + QString::number(i);
                        users.append(user);
                    }

                    QJsonObject message;
                    message["count"] = userCount;
                    message["entries"] = users;
                    message["hash"] = "29234e32274a32276e25666a42";
                    message["version"] = "2.1.2";
                    message["success"] = "true";
                    message["id"] = "testclient";
                    message["nonce"] = nonce;

                    QString replyMessage(QJsonDocument(message).toJson());
                    QJsonObject response;
                    response["action"] = valStr;
                    response["message"] = Encrypt(replyMessage, nonce);
                    response["nonce"] = nonce;

                    SendReply(response);
                }
            }
        }
        else
        {
            AppendText("Cannot decrypt message");
        }
    }
    else
    {
        AppendText("No message received");
    }
}

void ChromeListener::HandleGeneratePassword(const QJsonObject &json, const QString &valStr)
{
    QString nonce = json.value("nonce").toString();
    QString generatedPassword = "testpassword";

    QJsonArray arr;
    QJsonObject passwd;
    passwd["login"] = generatedPassword.length() * 8; // bits
    passwd["password"] = generatedPassword;
    arr.append(passwd);

    QJsonObject message;
    message["version"] = "2.1.2";
    message["success"] = "true";
    message["entries"] = arr;
    message["nonce"] = nonce;

    QString replyMessage(QJsonDocument(message).toJson());
    QJsonObject response;
    response["action"] = valStr;
    response["message"] = Encrypt(replyMessage, nonce);
    response["nonce"] = nonce;

    SendReply(response);
}

void ChromeListener::HandleSetLogin(const QJsonObject &json, const QString &valStr)
{
    QString nonce = json.value("nonce").toString();
    QString encrypted = json.value("message").toString();
    if (encrypted.length() > 0)
    {
        QByteArray ba = Decrypt(encrypted, nonce);
        if (ba.length() > 0)
        {
            AppendText("Message decrypted: " + QString(ba));
            QJsonObject json = GetJSonObject(ba);
            if (!json.isEmpty())
            {
                QJsonValue val = json.value("url");
                if (val.isString())
                {
                   AppendText("URL: " + val.toString());

                    QJsonObject message;
                    message["count"] = QJsonValue::Null;
                    message["entries"] = QJsonValue::Null;
                    message["error"] = "";
                    message["hash"] = "29234e32274a32276e25666a42";
                    message["version"] = "2.1.2";
                    message["success"] = "true";
                    message["nonce"] = nonce;

                    QString replyMessage(QJsonDocument(message).toJson());
                    QJsonObject response;
                    response["action"] = valStr;
                    response["message"] = Encrypt(replyMessage, nonce);
                    response["nonce"] = nonce;

                    SendReply(response);
                }
            }
        }
        else
        {
            AppendText("Cannot decrypt message");
        }
    }
    else
    {
        AppendText("No message received");
    }
}

void ChromeListener::AppendText(const QString &str)
{

}

void ChromeListener::SendReply(const QJsonObject json)
{
    QString reply(QJsonDocument(json).toJson());
    uint len = reply.length();

    std::cout << char(((len>>0) & 0xFF))
                << char(((len>>8) & 0xFF))
                << char(((len>>16) & 0xFF))
                << char(((len>>24) & 0xFF));
    std::cout << reply.toStdString() << std::flush;

    AppendText(reply);
}

QString ChromeListener::Encrypt(const QString decrypted, const QString nonce) const
{
    QString result;
    unsigned char n[crypto_box_NONCEBYTES];
    unsigned char ck[crypto_box_PUBLICKEYBYTES];
    unsigned char sk[crypto_box_SECRETKEYBYTES];
    unsigned char m[MESSAGE_LENGTH] = {0};
    unsigned char e[MESSAGE_LENGTH] = {0};

    const QByteArray ma = decrypted.toUtf8();
    const QByteArray na = base64Decode(nonce);
    const QByteArray ca = base64Decode(m_ClientPublicKey);
    const QByteArray sa = base64Decode(m_SecretKey);

    std::memcpy(m, ma.toStdString().data(), ma.length());
    std::memcpy(n, na.toStdString().data(), na.length());
    std::memcpy(ck, ca.toStdString().data(), ca.length());
    std::memcpy(sk, sa.toStdString().data(), sa.length());

    if (crypto_box_easy(e, m, ma.length(), n, ck, sk) == 0)
    {
        QByteArray res = getQByteArray(e, (crypto_box_MACBYTES + ma.length()));
        result = res.toBase64();
    }

    return result;
}

QByteArray ChromeListener::Decrypt(const QString encrypted, const QString nonce) const
{
    QByteArray result;
    unsigned char n[crypto_box_NONCEBYTES];
    unsigned char ck[crypto_box_PUBLICKEYBYTES];
    unsigned char sk[crypto_box_SECRETKEYBYTES];
    unsigned char m[MESSAGE_LENGTH] = {0};
    unsigned char d[MESSAGE_LENGTH] = {0};

    const QByteArray ma = base64Decode(encrypted);
    const QByteArray na = base64Decode(nonce);
    const QByteArray ca = base64Decode(m_ClientPublicKey);
    const QByteArray sa = base64Decode(m_SecretKey);

    std::memcpy(m, ma.toStdString().data(), ma.length());
    std::memcpy(n, na.toStdString().data(), na.length());
    std::memcpy(ck, ca.toStdString().data(), ca.length());
    std::memcpy(sk, sa.toStdString().data(), sa.length());

    if (crypto_box_open_easy(d, m, ma.length(), n, ck, sk) == 0)
    {
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
    for (uint i = 0; i < len; i++)
    {
        qba.append(static_cast<char>(array[i]));
    }
    return qba;
}

QJsonObject ChromeListener::GetJSonObject(const uchar* pArray, const uint len)
{
    QByteArray arr = getQByteArray(pArray, len);
    QJsonParseError err;
    QJsonDocument doc(QJsonDocument::fromJson(arr, &err));

    if (!doc.isObject())
    {
        //AppendText(err.errorString());
        // Error
    }

    return doc.object();
}

QJsonObject ChromeListener::GetJSonObject(const QByteArray ba)
{
    QJsonParseError err;
    QJsonDocument doc(QJsonDocument::fromJson(ba, &err));

    if (!doc.isObject())
    {
        //AppendText(err.errorString());
        // Error
    }

    return doc.object();
}

QByteArray ChromeListener::base64Decode(const QString str)
{
    return QByteArray::fromBase64(str.toUtf8());
}
