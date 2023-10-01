/*
 *  Copyright (C) 2023 KeePassXC Team <team@keepassxc.org>
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

#include "PasskeyImporter.h"
#include "PasskeyImportDialog.h"
#include "browser/BrowserPasskeys.h"
#include "core/Entry.h"
#include "core/Group.h"
#include "gui/FileDialog.h"
#include "gui/MessageBox.h"
#include <QFileInfo>
#include <QTextStream>
#include <QUuid>

static const QString IMPORTED_PASSKEYS_GROUP = QStringLiteral("Imported Passkeys");

void PasskeyImporter::importPasskey(QSharedPointer<Database>& database)
{
    Q_UNUSED(database)
    auto filter = QString("%1 (*.passkey);;%2 (*)").arg(tr("Passkey file"), tr("All files"));
    auto fileName =
        fileDialog()->getOpenFileName(nullptr, tr("Open Passkey file"), FileDialog::getLastDir("passkey"), filter);
    if (fileName.isEmpty()) {
        return;
    }

    FileDialog::saveLastDir("passkey", fileName, true);

    QFile file(fileName);
    if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        MessageBox::information(
            nullptr, tr("Cannot open file"), tr("Cannot open file \"%1\" for reading.").arg(fileName));
        return;
    }

    importSelectedFile(file, database);
}

void PasskeyImporter::importSelectedFile(QFile& file, QSharedPointer<Database>& database)
{
    QTextStream fileStream(&file);
    const auto relyingParty = fileStream.readLine();
    const auto username = fileStream.readLine();
    const auto password = fileStream.readLine();
    const auto userHandle = fileStream.readLine();

    QString privateKey;
    while (!fileStream.atEnd()) {
        privateKey.append(fileStream.readLine() + "\n");
    }

    if (relyingParty.isEmpty() || username.isEmpty() || password.isEmpty() || userHandle.isEmpty()
        || privateKey.isEmpty()) {
        MessageBox::information(nullptr,
                                tr("Cannot import Passkey"),
                                tr("Cannot import Passkey file \"%1\". Data is missing.").arg(file.fileName()));
        return;
    } else if (!privateKey.startsWith("-----BEGIN PRIVATE KEY-----")
               || !privateKey.endsWith("-----END PRIVATE KEY-----\n")) {
        MessageBox::information(
            nullptr,
            tr("Cannot import Passkey"),
            tr("Cannot import Passkey file \"%1\". Private key is missing or malformed.").arg(file.fileName()));
        return;
    }

    showImportDialog(
        database, QFileInfo(file).completeBaseName(), relyingParty, username, password, userHandle, privateKey);
}

void PasskeyImporter::showImportDialog(QSharedPointer<Database>& database,
                                       const QString& filename,
                                       const QString& relyingParty,
                                       const QString& username,
                                       const QString& password,
                                       const QString& userHandle,
                                       const QString& privateKey)
{
    Q_UNUSED(filename)
    PasskeyImportDialog passkeyImportDialog;
    passkeyImportDialog.setInfo(relyingParty, username, database);

    auto ret = passkeyImportDialog.exec();
    if (ret != QDialog::Accepted) {
        return;
    }

    auto db = passkeyImportDialog.getSelectedDatabase();
    if (!db) {
        db = database;
    }

    auto entry = new Entry();

    // Apply group settings
    auto useDefaultGroup = passkeyImportDialog.useDefaultGroup();
    if (useDefaultGroup) {
        auto defaultGroup = db->rootGroup()->findGroupByPath(IMPORTED_PASSKEYS_GROUP);
        if (!defaultGroup) {
            auto newGroup = new Group();
            newGroup->setName(IMPORTED_PASSKEYS_GROUP);
            newGroup->setUuid(QUuid::createUuid());
            newGroup->setParent(db->rootGroup());
            entry->setGroup(newGroup);
        } else {
            entry->setGroup(defaultGroup);
        }
    } else {
        auto groupUuid = passkeyImportDialog.getSelectedGroupUuid();
        auto group = db->rootGroup()->findGroupByUuid(groupUuid);
        if (!group) {
            return;
        }

        entry->setGroup(group);
    }

    entry->setUuid(QUuid::createUuid());
    entry->setTitle(QString("%1 (%2)").arg(relyingParty, tr("Passkey")));
    entry->setUsername(username);
    entry->attributes()->set(BrowserPasskeys::KPEX_PASSKEY_USERNAME, username, true);
    entry->attributes()->set(BrowserPasskeys::KPEX_PASSKEY_RELYING_PARTY, relyingParty);
    entry->attributes()->set(BrowserPasskeys::KPEX_PASSKEY_GENERATED_USER_ID, password, true);
    entry->attributes()->set(BrowserPasskeys::KPEX_PASSKEY_USER_HANDLE, userHandle, true);
    entry->attributes()->set(BrowserPasskeys::KPEX_PASSKEY_PRIVATE_KEY_PEM, privateKey, true);
}
