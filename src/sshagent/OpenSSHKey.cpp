/*
 *  Copyright (C) 2017 Toni Spets <toni.spets@iki.fi>
 *  Copyright (C) 2017 KeePassXC Team <team@keepassxc.org>
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

#include "OpenSSHKey.h"
#include <QRegularExpression>
#include <QStringList>
#include <QCryptographicHash>
#include "crypto/SymmetricCipher.h"

// bcrypt_pbkdf.cpp
int bcrypt_pbkdf(const QByteArray& pass, const QByteArray& salt, QByteArray& key, quint32 rounds);

OpenSSHKey::OpenSSHKey(QObject *parent)
    : QObject(parent)
    , m_type(QString())
    , m_cipherName(QString("none"))
    , m_kdfName(QString("none"))
    , m_kdfOptions(QByteArray())
    , m_rawPrivateData(QByteArray())
    , m_publicData(QList<QByteArray>())
    , m_privateData(QList<QByteArray>())
    , m_comment(QString())
    , m_error(QString())
{

}

OpenSSHKey::OpenSSHKey(const OpenSSHKey& other)
    : QObject(nullptr)
    , m_type(other.m_type)
    , m_cipherName(other.m_cipherName)
    , m_kdfName(other.m_kdfName)
    , m_kdfOptions(other.m_kdfOptions)
    , m_rawPrivateData(other.m_rawPrivateData)
    , m_publicData(other.m_publicData)
    , m_privateData(other.m_privateData)
    , m_comment(other.m_comment)
    , m_error(other.m_error)
{

}

bool OpenSSHKey::operator==(const OpenSSHKey& other) const
{
    // close enough for now
    return (fingerprint() == other.fingerprint());
}

const QString OpenSSHKey::cipherName() const
{
    return m_cipherName;
}

const QString OpenSSHKey::type() const
{
    return m_type;
}

int OpenSSHKey::keyLength() const
{
    if (m_type == "ssh-dss" && m_publicData.length() == 4) {
        return (m_publicData[0].length() - 1) * 8;
    } else if (m_type == "ssh-rsa" && m_publicData.length() == 2) {
        return (m_publicData[1].length() - 1) * 8;
    } else if (m_type.startsWith("ecdsa-sha2-") && m_publicData.length() == 2) {
        return (m_publicData[1].length() - 1) * 4;
    } else if (m_type == "ssh-ed25519" && m_publicData.length() == 1) {
        return m_publicData[0].length() * 8;
    }

    return 0;
}

const QString OpenSSHKey::fingerprint() const
{
    QByteArray publicKey;
    BinaryStream stream(&publicKey);

    stream.writeString(m_type);

    for (QByteArray ba : m_publicData) {
        stream.writeString(ba);
    }

    QByteArray rawHash = QCryptographicHash::hash(publicKey, QCryptographicHash::Sha256);

    return "SHA256:" + QString::fromLatin1(rawHash.toBase64(QByteArray::OmitTrailingEquals));
}

const QString OpenSSHKey::comment() const
{
    return m_comment;
}

const QString OpenSSHKey::publicKey() const
{
    QByteArray publicKey;
    BinaryStream stream(&publicKey);

    stream.writeString(m_type);

    for (QByteArray ba : m_publicData) {
        stream.writeString(ba);
    }

    return m_type + " " + QString::fromLatin1(publicKey.toBase64()) + " " + m_comment;
}

const QString OpenSSHKey::errorString() const
{
    return m_error;
}

void OpenSSHKey::setType(const QString& type)
{
    m_type = type;
}

void OpenSSHKey::setPublicData(const QList<QByteArray>& data)
{
    m_publicData = data;
}

void OpenSSHKey::setPrivateData(const QList<QByteArray>& data)
{
    m_privateData = data;
}

void OpenSSHKey::setComment(const QString& comment)
{
    m_comment = comment;
}

void OpenSSHKey::clearPrivate()
{
    m_rawPrivateData.clear();
    m_privateData.clear();
}

bool OpenSSHKey::parsePEM(const QByteArray& in, QByteArray& out)
{
    QString pem = QString::fromLatin1(in);
    QStringList rows = pem.split(QRegularExpression("(?:\r?\n|\r)"), QString::SkipEmptyParts);

    if (rows.length() < 3) {
        m_error = tr("Invalid key file, expecting an OpenSSH key");
        return false;
    }

    QString begin = rows.first();
    QString end = rows.last();

    QRegularExpressionMatch beginMatch = QRegularExpression("^-----BEGIN ([^\\-]+)-----$").match(begin);
    QRegularExpressionMatch endMatch = QRegularExpression("^-----END ([^\\-]+)-----$").match(end);

    if (!beginMatch.hasMatch() || !endMatch.hasMatch()) {
        m_error = tr("Invalid key file, expecting an OpenSSH key");
        return false;
    }

    if (beginMatch.captured(1) != endMatch.captured(1)) {
        m_error = tr("PEM boundary mismatch");
        return false;
    }

    if (beginMatch.captured(1) != "OPENSSH PRIVATE KEY") {
        m_error = tr("This is not an OpenSSH key, only modern keys are supported");
        return false;
    }

    rows.removeFirst();
    rows.removeLast();

    out = QByteArray::fromBase64(rows.join("").toLatin1());

    if (out.isEmpty()) {
        m_error = tr("Base64 decoding failed");
        return false;
    }

    return true;
}

bool OpenSSHKey::parse(const QByteArray& in)
{
    QByteArray data;

    if (!parsePEM(in, data)) {
        return false;
    }

    BinaryStream stream(&data);

    QByteArray magic;
    magic.resize(15);

    if (!stream.read(magic)) {
        m_error = tr("Key file way too small.");
        return false;
    }

    if (QString::fromLatin1(magic) != "openssh-key-v1") {
        m_error = tr("Key file magic header id invalid");
        return false;
    }

    stream.readString(m_cipherName);
    stream.readString(m_kdfName);
    stream.readString(m_kdfOptions);

    quint32 numberOfKeys;
    stream.read(numberOfKeys);

    if (numberOfKeys == 0) {
        m_error = tr("Found zero keys");
        return false;
    }

    for (quint32 i = 0; i < numberOfKeys; ++i) {
        QByteArray publicKey;
        if (!stream.readString(publicKey)) {
            m_error = tr("Failed to read public key.");
            return false;
        }

        if (i == 0) {
            BinaryStream publicStream(&publicKey);
            if (!readPublic(publicStream)) {
                return false;
            }
        }
    }

    // padded list of keys
    if (!stream.readString(m_rawPrivateData)) {
        m_error = tr("Corrupted key file, reading private key failed");
        return false;
    }

    // load private if no encryption
    if (!encrypted()) {
        return openPrivateKey();
    }

    return true;
}

bool OpenSSHKey::encrypted() const
{
    return (m_cipherName != "none");
}

bool OpenSSHKey::openPrivateKey(const QString& passphrase)
{
    QScopedPointer<SymmetricCipher> cipher;

    if (!m_privateData.isEmpty()) {
        return true;
    }

    if (m_rawPrivateData.isEmpty()) {
        m_error = tr("No private key payload to decrypt");
        return false;
    }

    if (m_cipherName == "aes256-cbc") {
        cipher.reset(new SymmetricCipher(SymmetricCipher::Aes256, SymmetricCipher::Cbc, SymmetricCipher::Decrypt));
    } else if (m_cipherName == "aes256-ctr") {
        cipher.reset(new SymmetricCipher(SymmetricCipher::Aes256, SymmetricCipher::Ctr, SymmetricCipher::Decrypt));
    } else if (m_cipherName != "none") {
        m_error = tr("Unknown cipher: ") + m_cipherName;
        return false;
    }

    if (m_kdfName == "bcrypt") {
        if (!cipher) {
            m_error = tr("Trying to run KDF without cipher");
            return false;
        }

        if (passphrase.length() == 0) {
            m_error = tr("Passphrase is required to decrypt this key");
            return false;
        }

        BinaryStream optionStream(&m_kdfOptions);

        QByteArray salt;
        quint32 rounds;

        optionStream.readString(salt);
        optionStream.read(rounds);

        QByteArray decryptKey;
        decryptKey.fill(0, cipher->keySize() + cipher->blockSize());

        QByteArray phraseData = passphrase.toLatin1();
        if (bcrypt_pbkdf(phraseData, salt, decryptKey, rounds) < 0) {
            m_error = tr("Key derivation failed, key file corrupted?");
            return false;
        }

        QByteArray keyData, ivData;
        keyData.setRawData(decryptKey.data(), cipher->keySize());
        ivData.setRawData(decryptKey.data() + cipher->keySize(), cipher->blockSize());

        cipher->init(keyData, ivData);
    } else if (m_kdfName != "none") {
        m_error = tr("Unknown KDF: ") + m_kdfName;
        return false;
    }

    QByteArray rawPrivateData = m_rawPrivateData;

    if (cipher && cipher->isInitalized()) {
        bool ok = false;
        rawPrivateData = cipher->process(rawPrivateData, &ok);
        if (!ok) {
            m_error = tr("Decryption failed, wrong passphrase?");
            return false;
        }
    }

    BinaryStream keyStream(&rawPrivateData);

    quint32 checkInt1;
    quint32 checkInt2;

    keyStream.read(checkInt1);
    keyStream.read(checkInt2);

    if (checkInt1 != checkInt2) {
        m_error = tr("Decryption failed, wrong passphrase?");
        return false;
    }

    return readPrivate(keyStream);
}

bool OpenSSHKey::readPublic(BinaryStream& stream)
{
    m_publicData.clear();

    if (!stream.readString(m_type)) {
        m_error = tr("Unexpected EOF while reading public key");
        return false;
    }

    int keyParts;
    if (m_type == "ssh-dss") {
        keyParts = 4;
    } else if (m_type == "ssh-rsa") {
        keyParts = 2;
    } else if (m_type.startsWith("ecdsa-sha2-")) {
        keyParts = 2;
    } else if (m_type == "ssh-ed25519") {
        keyParts = 1;
    } else {
        m_error = tr("Unknown key type: ") + m_type;
        return false;
    }

    for (int i = 0; i < keyParts; ++i) {
        QByteArray t;

        if (!stream.readString(t)) {
            m_error = tr("Unexpected EOF while reading public key");
            return false;
        }

        m_publicData.append(t);
    }

    return true;
}

bool OpenSSHKey::readPrivate(BinaryStream& stream)
{
    m_privateData.clear();

    if (!stream.readString(m_type)) {
        m_error = tr("Unexpected EOF while reading private key");
        return false;
    }

    int keyParts;
    if (m_type == "ssh-dss") {
        keyParts = 5;
    } else if (m_type == "ssh-rsa") {
        keyParts = 6;
    } else if (m_type.startsWith("ecdsa-sha2-")) {
        keyParts = 3;
    } else if (m_type == "ssh-ed25519") {
        keyParts = 2;
    } else {
        m_error = tr("Unknown key type: ") + m_type;
        return false;
    }

    for (int i = 0; i < keyParts; ++i) {
        QByteArray t;

        if (!stream.readString(t)) {
            m_error = tr("Unexpected EOF while reading private key");
            return false;
        }

        m_privateData.append(t);
    }

    if (!stream.readString(m_comment)) {
        m_error = tr("Unexpected EOF while reading private key");
        return false;
    }

    return true;
}

bool OpenSSHKey::writePublic(BinaryStream& stream)
{
    if (m_publicData.isEmpty()) {
        m_error = tr("Can't write public key as it is empty");
        return false;
    }

    if (!stream.writeString(m_type)) {
        m_error = tr("Unexpected EOF when writing public key");
        return false;
    }

    for (QByteArray t : m_publicData) {
        if (!stream.writeString(t)) {
            m_error = tr("Unexpected EOF when writing public key");
            return false;
        }
    }

    return true;
}

bool OpenSSHKey::writePrivate(BinaryStream& stream)
{
    if (m_privateData.isEmpty()) {
        m_error = tr("Can't write private key as it is empty");
        return false;
    }

    if (!stream.writeString(m_type)) {
        m_error = tr("Unexpected EOF when writing private key");
        return false;
    }

    for (QByteArray t : m_privateData) {
        if (!stream.writeString(t)) {
            m_error = tr("Unexpected EOF when writing private key");
            return false;
        }
    }

    if (!stream.writeString(m_comment)) {
        m_error = tr("Unexpected EOF when writing private key");
        return false;
    }

    return true;
}

uint qHash(const OpenSSHKey& key)
{
    return qHash(key.fingerprint());
}
