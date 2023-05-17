/*
 *  Copyright (C) 2022 KeePassXC Team <team@keepassxc.org>
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

#include "BrowserWebAuthn.h"
#include "BrowserMessageBuilder.h"
#include "BrowserService.h"
#include "crypto/Random.h"
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QtEndian>

#include <botan/data_src.h>
#include <botan/ec_group.h>
#include <botan/ecdsa.h>
#include <botan/pkcs8.h>
#include <botan/pubkey.h>
#include <botan/rsa.h>
#include <botan/sodium.h>

#include <bitset>

Q_GLOBAL_STATIC(BrowserWebAuthn, s_browserWebAuthn);

const QString BrowserWebAuthn::PUBLIC_KEY = QStringLiteral("public-key");
const QString BrowserWebAuthn::REQUIREMENT_DISCOURAGED = QStringLiteral("discouraged");
const QString BrowserWebAuthn::REQUIREMENT_PREFERRED = QStringLiteral("preferred");
const QString BrowserWebAuthn::REQUIREMENT_REQUIRED = QStringLiteral("required");

BrowserWebAuthn* BrowserWebAuthn::instance()
{
    return s_browserWebAuthn;
}

PublicKeyCredential BrowserWebAuthn::buildRegisterPublicKeyCredential(const QJsonObject& publicKeyCredentialOptions,
                                                                      const QString& origin,
                                                                      const PredefinedVariables& predefinedVariables)
{
    QJsonObject publicKeyCredential;
    const auto id = predefinedVariables.credentialId.isEmpty()
                        ? browserMessageBuilder()->getRandomBytesAsBase64(ID_BYTES)
                        : predefinedVariables.credentialId;

    // Extensions
    auto extensionObject = publicKeyCredentialOptions["extensions"].toObject();
    const auto extensionData = buildExtensionData(extensionObject);
    const auto extensions = browserMessageBuilder()->getBase64FromArray(extensionData);

    // Response
    QJsonObject responseObject;
    const auto clientData = buildClientDataJson(publicKeyCredentialOptions, origin, false);
    const auto attestationObject =
        buildAttestationObject(publicKeyCredentialOptions, extensions, id, predefinedVariables);
    responseObject["clientDataJSON"] = browserMessageBuilder()->getBase64FromJson(clientData);
    responseObject["attestationObject"] = browserMessageBuilder()->getBase64FromArray(attestationObject.cborEncoded);

    // PublicKeyCredential
    publicKeyCredential["authenticatorAttachment"] = QString("platform");
    publicKeyCredential["id"] = id;
    publicKeyCredential["response"] = responseObject;
    publicKeyCredential["type"] = PUBLIC_KEY;

    return {id, publicKeyCredential, attestationObject.pem};
}

QJsonObject BrowserWebAuthn::buildGetPublicKeyCredential(const QJsonObject& publicKeyCredentialRequestOptions,
                                                         const QString& origin,
                                                         const QString& id,
                                                         const QString& privateKeyPem)
{
    const auto authenticatorData = buildGetAttestationObject(publicKeyCredentialRequestOptions);
    const auto clientData = buildClientDataJson(publicKeyCredentialRequestOptions, origin, true);
    const auto clientDataArray = QJsonDocument(clientData).toJson(QJsonDocument::Compact);
    const auto signature = buildSignature(authenticatorData, clientDataArray, privateKeyPem);

    QJsonObject responseObject;
    responseObject["authenticatorData"] = browserMessageBuilder()->getBase64FromArray(authenticatorData);
    responseObject["clientDataJSON"] = browserMessageBuilder()->getBase64FromArray(clientDataArray);
    responseObject["signature"] = browserMessageBuilder()->getBase64FromArray(signature);

    QJsonObject publicKeyCredential;
    publicKeyCredential["authenticatorAttachment"] = QString("platform");
    publicKeyCredential["id"] = id;
    publicKeyCredential["response"] = responseObject;
    publicKeyCredential["type"] = PUBLIC_KEY;

    return publicKeyCredential;
}

bool BrowserWebAuthn::isUserVerificationValid(const QString& userVerification) const
{
    return QStringList({REQUIREMENT_PREFERRED, REQUIREMENT_REQUIRED, REQUIREMENT_DISCOURAGED})
        .contains(userVerification);
}

// See https://w3c.github.io/webauthn/#sctn-createCredential for default timeout values when not set in the request
int BrowserWebAuthn::getTimeout(const QString& userVerification, int timeout) const
{
    if (timeout == 0) {
        return userVerification == REQUIREMENT_DISCOURAGED ? DEFAULT_DISCOURAGED_TIMEOUT : DEFAULT_TIMEOUT;
    }

    return timeout;
}

QStringList BrowserWebAuthn::getAllowedCredentialsFromPublicKey(const QJsonObject& publicKey) const
{
    QStringList allowedCredentials;
    for (const auto& cred : publicKey["allowCredentials"].toArray()) {
        const auto c = cred.toObject();
        const auto id = c["id"].toString();

        if (c["type"].toString() == PUBLIC_KEY && !id.isEmpty()) {
            allowedCredentials << id;
        }
    }

    return allowedCredentials;
}

QJsonObject BrowserWebAuthn::buildClientDataJson(const QJsonObject& publicKey, const QString& origin, bool get)
{
    QJsonObject clientData;
    clientData["challenge"] = publicKey["challenge"];
    clientData["crossOrigin"] = false;
    clientData["origin"] = origin;
    clientData["type"] = get ? QString("webauthn.get") : QString("webauthn.create");

    return clientData;
}

// https://w3c.github.io/webauthn/#attestation-object
PrivateKey BrowserWebAuthn::buildAttestationObject(const QJsonObject& publicKey,
                                                   const QString& extensions,
                                                   const QString& id,
                                                   const PredefinedVariables& predefinedVariables)
{
    QByteArray result;

    // Create SHA256 hash from rpId
    const auto rpIdHash = browserMessageBuilder()->getSha256Hash(publicKey["rp"]["id"].toString());
    result.append(rpIdHash);

    // Use default flags
    const auto flags =
        setFlagsFromJson(QJsonObject({{"ED", !extensions.isEmpty()},
                                      {"AT", true},
                                      {"BS", false},
                                      {"BE", false},
                                      {"UV", publicKey["userVerification"].toString() != REQUIREMENT_DISCOURAGED},
                                      {"UP", true}}));
    result.append(flags);

    // Signature counter (not supported, always 0
    const char counter[4] = {0x00, 0x00, 0x00, 0x00};
    result.append(QByteArray::fromRawData(counter, 4));

    // AAGUID (use the default/non-set)
    result.append("\x01\x02\x03\x04\x05\x06\x07\b\x01\x02\x03\x04\x05\x06\x07\b");

    // Credential length
    const char credentialLength[2] = {0x00, 0x20};
    result.append(QByteArray::fromRawData(credentialLength, 2));

    // Credential Id
    result.append(QByteArray::fromBase64(
        predefinedVariables.credentialId.isEmpty() ? id.toUtf8() : predefinedVariables.credentialId.toUtf8(),
        QByteArray::Base64UrlEncoding));

    // Credential private key
    const auto alg = getAlgorithmFromPublicKey(publicKey);
    const auto credentialPublicKey =
        buildCredentialPrivateKey(alg, predefinedVariables.first, predefinedVariables.second);
    result.append(credentialPublicKey.cborEncoded);

    // Add extension data if available
    if (!extensions.isEmpty()) {
        result.append(browserMessageBuilder()->getArrayFromBase64(extensions));
    }

    // The final result should be CBOR encoded
    return {m_browserCbor.cborEncodeAttestation(result), credentialPublicKey.pem};
}

// Build a short version of the attestation object for webauthn.get
QByteArray BrowserWebAuthn::buildGetAttestationObject(const QJsonObject& publicKey)
{
    QByteArray result;

    const auto rpIdHash = browserMessageBuilder()->getSha256Hash(publicKey["rpId"].toString());
    result.append(rpIdHash);

    const auto flags =
        setFlagsFromJson(QJsonObject({{"ED", false},
                                      {"AT", false},
                                      {"BS", false},
                                      {"BE", false},
                                      {"UV", publicKey["userVerification"].toString() != REQUIREMENT_DISCOURAGED},
                                      {"UP", true}}));
    result.append(flags);

    // Signature counter (not supported, always 0
    const char counter[4] = {0x00, 0x00, 0x00, 0x00};
    result.append(QByteArray::fromRawData(counter, 4));

    return result;
}

// See: https://w3c.github.io/webauthn/#sctn-encoded-credPubKey-examples
PrivateKey
BrowserWebAuthn::buildCredentialPrivateKey(int alg, const QString& predefinedFirst, const QString& predefinedSecond)
{
    // Only support -7, P256 (EC) and -257 (RSA) for now
    if (alg != WebAuthnAlgorithms::ES256 && alg != WebAuthnAlgorithms::RS256) {
        return {};
    }

    QByteArray firstPart;
    QByteArray secondPart;
    QByteArray pem;

    if (!predefinedFirst.isEmpty() && !predefinedSecond.isEmpty()) {
        firstPart = browserMessageBuilder()->getArrayFromBase64(predefinedFirst);
        secondPart = browserMessageBuilder()->getArrayFromBase64(predefinedSecond);
    } else {
        if (alg == WebAuthnAlgorithms::ES256) {
            try {
                Botan::ECDSA_PrivateKey privateKey(*randomGen()->getRng(), Botan::EC_Group("secp256r1"));
                const auto& publicPoint = privateKey.public_point();
                auto x = publicPoint.get_affine_x();
                auto y = publicPoint.get_affine_y();
                firstPart = bigIntToQByteArray(x);
                secondPart = bigIntToQByteArray(y);

                auto privateKeyPem = Botan::PKCS8::PEM_encode(privateKey);
                pem = QByteArray::fromStdString(privateKeyPem);
            } catch (std::exception& e) {
                qWarning("BrowserWebAuthn::buildCredentialPrivateKey: Could not create EC2 private key: %s", e.what());
                return {};
            }
        } else if (alg == WebAuthnAlgorithms::RS256) {
            try {
                Botan::RSA_PrivateKey privateKey(*randomGen()->getRng(), RSA_BITS, RSA_EXPONENT);
                auto modulus = privateKey.get_n();
                auto exponent = privateKey.get_e();
                firstPart = bigIntToQByteArray(modulus);
                secondPart = bigIntToQByteArray(exponent);

                auto privateKeyPem = Botan::PKCS8::PEM_encode(privateKey);
                pem = QByteArray::fromStdString(privateKeyPem);
            } catch (std::exception& e) {
                qWarning("BrowserWebAuthn::buildCredentialPrivateKey: Could not create RSA private key: %s", e.what());
                return {};
            }
        }
    }

    auto result = m_browserCbor.cborEncodePublicKey(alg, firstPart, secondPart);
    return {result, pem};
}

QByteArray BrowserWebAuthn::buildSignature(const QByteArray& authenticatorData,
                                           const QByteArray& clientData,
                                           const QString& privateKeyPem)
{
    const auto clientDataHash = browserMessageBuilder()->getSha256Hash(clientData);
    const auto attToBeSigned = authenticatorData + clientDataHash;

    try {
        const auto privateKeyArray = privateKeyPem.toUtf8();
        Botan::DataSource_Memory dataSource(reinterpret_cast<const uint8_t*>(privateKeyArray.constData()),
                                            privateKeyArray.size());

        const auto key = Botan::PKCS8::load_key(dataSource).release();
        const auto privateKeyBytes = key->private_key_bits();
        const auto algName = key->algo_name();
        const auto algId = key->algorithm_identifier();

        std::vector<uint8_t> rawSignature;
        if (algName == "ECDSA") {
            Botan::ECDSA_PrivateKey privateKey(algId, privateKeyBytes);
#ifdef WITH_XC_BOTAN3
            Botan::PK_Signer signer(
                privateKey, *randomGen()->getRng(), "EMSA1(SHA-256)", Botan::Signature_Format::DerSequence);
#else
            Botan::PK_Signer signer(privateKey, *randomGen()->getRng(), "EMSA1(SHA-256)", Botan::DER_SEQUENCE);
#endif

            signer.update(reinterpret_cast<const uint8_t*>(attToBeSigned.constData()), attToBeSigned.size());
            rawSignature = signer.signature(*randomGen()->getRng());
        } else if (algName == "RSA") {
            Botan::RSA_PrivateKey privateKey(algId, privateKeyBytes);
            Botan::PK_Signer signer(privateKey, *randomGen()->getRng(), "EMSA3(SHA-256)");

            signer.update(reinterpret_cast<const uint8_t*>(attToBeSigned.constData()), attToBeSigned.size());
            rawSignature = signer.signature(*randomGen()->getRng());
        } else {
            qWarning("BrowserWebAuthn::buildSignature: Algorithm not supported");
            return {};
        }

        auto signature = QByteArray(reinterpret_cast<char*>(rawSignature.data()), rawSignature.size());
        return signature;
    } catch (std::exception& e) {
        qWarning("BrowserWebAuthn::buildSignature: Could not sign key: %s", e.what());
        return {};
    }
}

QByteArray BrowserWebAuthn::buildExtensionData(QJsonObject& extensionObject) const
{
    // Only supports "credProps" and "uvm" for now
    const QStringList allowedKeys = {"credProps", "uvm"};

    // Remove unsupported keys
    for (const auto& key : extensionObject.keys()) {
        if (!allowedKeys.contains(key)) {
            extensionObject.remove(key);
        }
    }

    auto extensionData = m_browserCbor.cborEncodeExtensionData(extensionObject);
    if (!extensionData.isEmpty()) {
        return extensionData;
    }

    return {};
}

// Parse authentication data byte array to JSON
// See: https://www.w3.org/TR/webauthn/images/fido-attestation-structures.svg
// And: https://w3c.github.io/webauthn/#attested-credential-data
QJsonObject BrowserWebAuthn::parseAuthData(const QByteArray& authData) const
{
    auto rpIdHash = authData.mid(AuthDataOffsets::RPIDHASH, HASH_BYTES);
    auto flags = authData.mid(AuthDataOffsets::FLAGS, 1);
    auto counter = authData.mid(AuthDataOffsets::SIGNATURE_COUNTER, 4);
    auto aaGuid = authData.mid(AuthDataOffsets::AAGUID, 16);
    auto credentialLength = authData.mid(AuthDataOffsets::CREDENTIAL_LENGTH, 2);
    auto credLen = qFromBigEndian<quint16>(credentialLength.data());
    auto credentialId = authData.mid(AuthDataOffsets::CREDENTIAL_ID, credLen);
    auto publicKey = authData.mid(AuthDataOffsets::CREDENTIAL_ID + credLen);

    QJsonObject credentialDataJson({{"aaguid", browserMessageBuilder()->getBase64FromArray(aaGuid)},
                                    {"credentialId", browserMessageBuilder()->getBase64FromArray(credentialId)},
                                    {"publicKey", m_browserCbor.getJsonFromCborData(publicKey)}});

    QJsonObject result({{"credentialData", credentialDataJson},
                        {"flags", parseFlags(flags)},
                        {"rpIdHash", browserMessageBuilder()->getBase64FromArray(rpIdHash)},
                        {"signatureCounter", QJsonValue(qFromBigEndian<int>(counter))}});

    return result;
}

// See: https://w3c.github.io/webauthn/#table-authData
QJsonObject BrowserWebAuthn::parseFlags(const QByteArray& flags) const
{
    if (flags.isEmpty()) {
        return {};
    }

    auto flagsByte = static_cast<uint8_t>(flags[0]);
    std::bitset<8> flagBits(flagsByte);

    return QJsonObject({{"ED", flagBits.test(AuthenticatorFlags::ED)},
                        {"AT", flagBits.test(AuthenticatorFlags::AT)},
                        {"BS", flagBits.test(AuthenticatorFlags::BS)},
                        {"BE", flagBits.test(AuthenticatorFlags::BE)},
                        {"UV", flagBits.test(AuthenticatorFlags::UV)},
                        {"UP", flagBits.test(AuthenticatorFlags::UP)}});
}

char BrowserWebAuthn::setFlagsFromJson(const QJsonObject& flags) const
{
    if (flags.isEmpty()) {
        return 0;
    }

    char flagBits = 0x00;
    auto setFlag = [&](const char* key, unsigned char bit) {
        if (flags[key].toBool()) {
            flagBits |= 1 << bit;
        }
    };

    setFlag("ED", AuthenticatorFlags::ED);
    setFlag("AT", AuthenticatorFlags::AT);
    setFlag("BS", AuthenticatorFlags::BS);
    setFlag("BE", AuthenticatorFlags::BE);
    setFlag("UV", AuthenticatorFlags::UV);
    setFlag("UP", AuthenticatorFlags::UP);

    return flagBits;
}

// Returns the first supported algorithm from the pubKeyCredParams list (only support ES256 and RS256 for now)
WebAuthnAlgorithms BrowserWebAuthn::getAlgorithmFromPublicKey(const QJsonObject& publicKey) const
{
    const auto pubKeyCredParams = publicKey["pubKeyCredParams"].toArray();
    if (!pubKeyCredParams.isEmpty()) {
        const auto alg = pubKeyCredParams.first()["alg"].toInt();
        if (alg == WebAuthnAlgorithms::ES256 || alg == WebAuthnAlgorithms::RS256) {
            return static_cast<WebAuthnAlgorithms>(alg);
        }
    }

    return WebAuthnAlgorithms::ES256;
}

QByteArray BrowserWebAuthn::bigIntToQByteArray(Botan::BigInt& bigInt) const
{
    return browserMessageBuilder()->getArrayFromHexString(bigInt.to_hex_string().c_str());
}
