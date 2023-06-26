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
#include "browser/BrowserService.h"
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
    const auto url = fileStream.readLine();
    const auto username = fileStream.readLine();
    const auto password = fileStream.readLine();

    QString fileAttachment;
    while (!fileStream.atEnd()) {
        fileAttachment.append(fileStream.readLine() + "\n");
    }

    if (url.isEmpty() || username.isEmpty() || password.isEmpty() || fileAttachment.isEmpty()) {
        MessageBox::information(nullptr,
                                tr("Cannot import Passkey"),
                                tr("Cannot import Passkey file \"%1\". Data is missing.").arg(file.fileName()));
        return;
    } else if (!fileAttachment.startsWith("-----BEGIN PRIVATE KEY-----")
               || !fileAttachment.endsWith("-----END PRIVATE KEY-----\n")) {
        MessageBox::information(
            nullptr,
            tr("Cannot import Passkey"),
            tr("Cannot import Passkey file \"%1\". Private key is missing or malformed.").arg(file.fileName()));
        return;
    }

    showImportDialog(database, url, username, password, fileAttachment, file);
}

void PasskeyImporter::showImportDialog(QSharedPointer<Database>& database,
                                       const QString& url,
                                       const QString& username,
                                       const QString& password,
                                       const QString& fileAttachment,
                                       QFile& file)
{
    PasskeyImportDialog passkeyImportDialog;
    passkeyImportDialog.setInfo(url, username, database);

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

    // Update entry data
    entry->beginUpdate();
    entry->setUuid(QUuid::createUuid());
    entry->setUrl(url);
    entry->setUsername(username);
    entry->setPassword(password);
    entry->setTitle(QString("%1 (%2)").arg(QFileInfo(file.fileName()).baseName(), tr("Passkey")));
    entry->attachments()->set(BrowserService::PASSKEYS_KEY_FILENAME, fileAttachment.toUtf8());
    entry->endUpdate();
}