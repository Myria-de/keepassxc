/*
 *  Copyright (C) 2022 KeePassXC Team <team@keepassxc.org>
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

#ifndef KEEPASSXC_TESTWEBAUTHN_H
#define KEEPASSXC_TESTWEBAUTHN_H

#include <QObject>

#include "browser/BrowserWebAuthn.h"

class TestWebAuthn : public QObject
{
    Q_OBJECT

private slots:
    void initTestCase();
    void init();

    void testBase64WithHexStrings();
    void testDecodeResponseData();

    void testLoadingECPrivateKeyFromPem();
    void testLoadingRSAPrivateKeyFromPem();
    void testCreatingAttestationObjectWithEC();
    void testCreatingAttestationObjectWithRSA();
    void testRegister();

    void testParseGetAuthData();
    void testGet();

    void testExtensions();
    void testParseFlags();
    void testSetFlags();
};
#endif // KEEPASSXC_TESTWEBAUTHN_H
