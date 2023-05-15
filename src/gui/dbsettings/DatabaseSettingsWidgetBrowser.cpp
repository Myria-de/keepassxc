/*
 *  Copyright (C) 2023 KeePassXC Team <team@keepassxc.org>
 *  Copyright (C) 2018 Sami Vänttinen <sami.vanttinen@protonmail.com>
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

#include "DatabaseSettingsWidgetBrowser.h"
#include "ui_DatabaseSettingsWidgetBrowser.h"

#include <QFileDialog>
#include <QProgressDialog>

#include "browser/BrowserService.h"
#include "browser/BrowserSettings.h"
#include "core/DatabaseSettings.h"
#include "core/FileHash.h"
#include "core/Group.h"
#include "core/Metadata.h"
#include "gui/MessageBox.h"

DatabaseSettingsWidgetBrowser::DatabaseSettingsWidgetBrowser(QWidget* parent)
    : DatabaseSettingsWidget(parent)
    , m_ui(new Ui::DatabaseSettingsWidgetBrowser())
    , m_customData(new CustomData(this))
    , m_customDataModel(new QStandardItemModel(this))
    , m_clientRestrictionDataModel(new QStandardItemModel(this))
{
    m_ui->setupUi(this);
    m_ui->removeCustomDataButton->setEnabled(false);
    m_ui->customDataTable->setModel(m_customDataModel);

    settingsWarning();

    m_ui->addAllowedProcessButton->setEnabled(false);
    m_ui->removeAllowedProcessButton->setEnabled(false);
    m_ui->clientRestrictionsTable->setEnabled(false);
    m_ui->clientRestrictionsTable->setModel(m_clientRestrictionDataModel);

    connect(m_ui->customDataTable->selectionModel(),
            SIGNAL(selectionChanged(QItemSelection, QItemSelection)),
            SLOT(toggleRemoveButton(QItemSelection)));
    connect(m_ui->customDataTable, SIGNAL(doubleClicked(QModelIndex)), SLOT(editIndex(QModelIndex)));
    connect(m_customDataModel, SIGNAL(itemChanged(QStandardItem*)), SLOT(editFinished(QStandardItem*)));

    connect(m_ui->removeCustomDataButton, SIGNAL(clicked()), SLOT(removeSelectedKey()));
    connect(m_ui->removeSharedEncryptionKeys, SIGNAL(clicked()), this, SLOT(removeSharedEncryptionKeys()));
    connect(m_ui->removeSharedEncryptionKeys, SIGNAL(clicked()), this, SLOT(updateSharedKeyList()));
    connect(m_ui->removeStoredPermissions, SIGNAL(clicked()), this, SLOT(removeStoredPermissions()));
    connect(m_ui->refreshDatabaseID, SIGNAL(clicked()), this, SLOT(refreshDatabaseID()));

    connect(m_ui->clientRestrictionsCheckbox, SIGNAL(clicked()), SLOT(clientRestrictionOptionChanged()));
    connect(m_ui->clientRestrictionsTable->selectionModel(),
            SIGNAL(selectionChanged(QItemSelection, QItemSelection)),
            SLOT(toggleRemoveProcessButton(QItemSelection)));
    connect(m_ui->addAllowedProcessButton, SIGNAL(clicked()), SLOT(addAllowedProcess()));
    connect(m_ui->removeAllowedProcessButton, SIGNAL(clicked()), SLOT(removeSelectedProcess()));
}

DatabaseSettingsWidgetBrowser::~DatabaseSettingsWidgetBrowser()
{
}

CustomData* DatabaseSettingsWidgetBrowser::customData() const
{
    // Returns the current database customData from metadata. Otherwise return an empty customData member.
    if (m_db) {
        return m_db->metadata()->customData();
    }
    return m_customData;
}

void DatabaseSettingsWidgetBrowser::initialize()
{
    updateModel();
    updateAllowedProcessesModel();
    settingsWarning();
}

void DatabaseSettingsWidgetBrowser::uninitialize()
{
}

void DatabaseSettingsWidgetBrowser::showEvent(QShowEvent* event)
{
    QWidget::showEvent(event);
}

bool DatabaseSettingsWidgetBrowser::save()
{
    return true;
}

void DatabaseSettingsWidgetBrowser::removeSelectedKey()
{
    if (MessageBox::Yes
        != MessageBox::question(this,
                                tr("Delete the selected key?"),
                                tr("Do you really want to delete the selected key?\n"
                                   "This may prevent connection to the browser plugin."),
                                MessageBox::Yes | MessageBox::Cancel,
                                MessageBox::Cancel)) {
        return;
    }

    const QItemSelectionModel* itemSelectionModel = m_ui->customDataTable->selectionModel();
    if (itemSelectionModel) {
        for (const QModelIndex& index : itemSelectionModel->selectedRows(0)) {
            QString key = index.data().toString();
            key.insert(0, CustomData::BrowserKeyPrefix);
            customData()->remove(key);
        }
        updateModel();
    }
}

void DatabaseSettingsWidgetBrowser::removeSelectedProcess()
{
    if (MessageBox::Yes
        != MessageBox::question(this,
                                tr("Remove the allowed process?"),
                                tr("Do you really want to remove the allowed?\n"
                                   "This will prevent connections from this client."),
                                MessageBox::Yes | MessageBox::Cancel,
                                MessageBox::Cancel)) {
        return;
    }

    const QItemSelectionModel* itemSelectionModel = m_ui->clientRestrictionsTable->selectionModel();
    if (itemSelectionModel) {
        for (const QModelIndex& index : itemSelectionModel->selectedRows(0)) {
            auto key = index.data().toString();
            key.insert(0, CustomData::OptionPrefix + CustomData::BrowserAllowedProcessPrefix);
            customData()->remove(key);
        }
        updateAllowedProcessesModel();
    }
}

void DatabaseSettingsWidgetBrowser::addAllowedProcess()
{
#ifdef Q_OS_WIN
    QString fileTypeFilter(QString("%1 (*.exe);;%2 (*.*)").arg(tr("Executable Files"), tr("All Files")));
#else
    QString fileTypeFilter(QString("%1 (*)").arg(tr("Executable Files")));
#endif
    auto processLocation = QFileDialog::getOpenFileName(this,
                                                        tr("Select allowed process"),
                                                        QFileInfo(QCoreApplication::applicationDirPath()).filePath(),
                                                        fileTypeFilter);

    // Add location and MD5 hash to table
    if (!processLocation.isEmpty()) {
        auto hash = FileHash::getFileHash(processLocation, QCryptographicHash::Md5, 8192);
        customData()->set(CustomData::OptionPrefix + CustomData::BrowserAllowedProcessPrefix + hash, processLocation);
        updateAllowedProcessesModel();
    }
}

void DatabaseSettingsWidgetBrowser::toggleRemoveButton(const QItemSelection& selected)
{
    m_ui->removeCustomDataButton->setEnabled(!selected.isEmpty());
}

void DatabaseSettingsWidgetBrowser::toggleRemoveProcessButton(const QItemSelection& selected)
{
    m_ui->removeAllowedProcessButton->setEnabled(!selected.isEmpty());
}

void DatabaseSettingsWidgetBrowser::updateModel()
{
    m_customDataModel->clear();
    m_customDataModel->setHorizontalHeaderLabels({tr("Key"), tr("Value"), tr("Created")});

    for (const QString& key : customData()->keys()) {
        if (key.startsWith(CustomData::BrowserKeyPrefix)) {
            QString strippedKey = key;
            strippedKey.remove(CustomData::BrowserKeyPrefix);
            auto created = customData()->value(QString("%1_%2").arg(CustomData::Created, strippedKey));
            auto createdItem = new QStandardItem(created);
            createdItem->setEditable(false);
            m_customDataModel->appendRow(QList<QStandardItem*>()
                                         << new QStandardItem(strippedKey)
                                         << new QStandardItem(customData()->value(key)) << createdItem);
        }
    }

    m_ui->removeCustomDataButton->setEnabled(false);
}

void DatabaseSettingsWidgetBrowser::updateAllowedProcessesModel()
{
    m_clientRestrictionDataModel->clear();
    m_clientRestrictionDataModel->setHorizontalHeaderLabels({tr("Hash"), tr("Path")});

    m_ui->removeAllowedProcessButton->setEnabled(false);
    m_ui->clientRestrictionsTable->setEnabled(false);
    m_ui->addAllowedProcessButton->setEnabled(false);

    auto clientRestrictionsEnabled = databaseSettings()->getClientRestrictions(m_db);
    if (!clientRestrictionsEnabled) {
        return;
    }

    m_ui->clientRestrictionsTable->setEnabled(true);
    m_ui->addAllowedProcessButton->setEnabled(true);

    for (const auto& key : customData()->keys()) {
        if (key.startsWith(CustomData::OptionPrefix + CustomData::BrowserAllowedProcessPrefix)) {
            auto strippedKey = key;
            strippedKey.remove(CustomData::OptionPrefix + CustomData::BrowserAllowedProcessPrefix);

            auto keyItem = new QStandardItem(strippedKey);
            auto valueItem = new QStandardItem(customData()->value(key));
            keyItem->setToolTip(strippedKey);
            valueItem->setToolTip(customData()->value(key));
            m_clientRestrictionDataModel->appendRow(QList<QStandardItem*>() << keyItem << valueItem);
        }
    }
}

void DatabaseSettingsWidgetBrowser::settingsWarning()
{
    if (!browserSettings()->isEnabled()) {
        m_ui->removeSharedEncryptionKeys->setEnabled(false);
        m_ui->removeStoredPermissions->setEnabled(false);
        m_ui->customDataTable->setEnabled(false);
        m_ui->warningWidget->showMessage(tr("Enable Browser Integration to access these settings."),
                                         MessageWidget::Warning);
        m_ui->warningWidget->setCloseButtonVisible(false);
        m_ui->warningWidget->setAutoHideTimeout(-1);
    } else {
        m_ui->removeSharedEncryptionKeys->setEnabled(true);
        m_ui->removeStoredPermissions->setEnabled(true);
        m_ui->customDataTable->setEnabled(true);
        m_ui->warningWidget->hideMessage();
    }
}

void DatabaseSettingsWidgetBrowser::removeSharedEncryptionKeys()
{
    if (MessageBox::Yes
        != MessageBox::question(this,
                                tr("Disconnect all browsers"),
                                tr("Do you really want to disconnect all browsers?\n"
                                   "This may prevent connection to the browser plugin."),
                                MessageBox::Yes | MessageBox::Cancel,
                                MessageBox::Cancel)) {
        return;
    }

    QStringList keysToRemove;
    for (const QString& key : m_db->metadata()->customData()->keys()) {
        if (key.startsWith(CustomData::BrowserKeyPrefix)) {
            keysToRemove << key;
        }
    }

    if (keysToRemove.isEmpty()) {
        MessageBox::information(this,
                                tr("KeePassXC: No keys found"),
                                tr("No shared encryption keys found in KeePassXC settings."),
                                MessageBox::Ok);
        return;
    }

    for (const QString& key : keysToRemove) {
        m_db->metadata()->customData()->remove(key);
    }

    const int count = keysToRemove.count();
    MessageBox::information(this,
                            tr("KeePassXC: Removed keys from database"),
                            tr("Successfully removed %n encryption key(s) from KeePassXC settings.", "", count),
                            MessageBox::Ok);
}

void DatabaseSettingsWidgetBrowser::removeStoredPermissions()
{
    if (MessageBox::Yes
        != MessageBox::question(this,
                                tr("Forget all site-specific settings on entries"),
                                tr("Do you really want forget all site-specific settings on every entry?\n"
                                   "Permissions to access entries will be revoked."),
                                MessageBox::Yes | MessageBox::Cancel,
                                MessageBox::Cancel)) {
        return;
    }

    QList<Entry*> entries = m_db->rootGroup()->entriesRecursive();

    QProgressDialog progress(tr("Removing stored permissions…"), tr("Abort"), 0, entries.count());
    progress.setWindowModality(Qt::WindowModal);

    uint counter = 0;
    for (Entry* entry : entries) {
        if (progress.wasCanceled()) {
            return;
        }

        if (entry->customData()->contains(BrowserService::KEEPASSXCBROWSER_NAME)) {
            entry->beginUpdate();
            entry->customData()->remove(BrowserService::KEEPASSXCBROWSER_NAME);
            entry->endUpdate();
            ++counter;
        }
        progress.setValue(progress.value() + 1);
    }
    progress.reset();

    if (counter > 0) {
        MessageBox::information(this,
                                tr("KeePassXC: Removed permissions"),
                                tr("Successfully removed permissions from %n entry(s).", "", counter),
                                MessageBox::Ok);
    } else {
        MessageBox::information(this,
                                tr("KeePassXC: No entry with permissions found!"),
                                tr("The active database does not contain an entry with permissions."),
                                MessageBox::Ok);
    }
}

void DatabaseSettingsWidgetBrowser::refreshDatabaseID()
{
    if (MessageBox::Yes
        != MessageBox::question(this,
                                tr("Refresh database ID"),
                                tr("Do you really want refresh the database ID?\n"
                                   "This is only necessary if your database is a copy of another and the "
                                   "browser extension cannot connect."),
                                MessageBox::Yes | MessageBox::Cancel,
                                MessageBox::Cancel)) {
        return;
    }

    m_db->rootGroup()->setUuid(QUuid::createUuid());
}

void DatabaseSettingsWidgetBrowser::editIndex(const QModelIndex& index)
{
    Q_ASSERT(index.isValid());
    if (!index.isValid()) {
        return;
    }

    m_valueInEdit = index.data().toString();
    m_ui->customDataTable->edit(index);
}

void DatabaseSettingsWidgetBrowser::editFinished(QStandardItem* item)
{
    const QItemSelectionModel* itemSelectionModel = m_ui->customDataTable->selectionModel();

    if (itemSelectionModel) {
        auto indexList = itemSelectionModel->selectedRows(item->column());
        if (indexList.length() > 0) {
            QString newValue = item->index().data().toString();

            // The key is edited
            if (item->column() == 0) {
                // Get the old key/value pair, remove it and replace it
                m_valueInEdit.insert(0, CustomData::BrowserKeyPrefix);
                auto tempValue = customData()->value(m_valueInEdit);
                newValue.insert(0, CustomData::BrowserKeyPrefix);

                m_db->metadata()->customData()->remove(m_valueInEdit);
                m_db->metadata()->customData()->set(newValue, tempValue);
            } else {
                // Replace just the value
                for (const QString& key : m_db->metadata()->customData()->keys()) {
                    if (key.startsWith(CustomData::BrowserKeyPrefix)) {
                        if (m_valueInEdit == m_db->metadata()->customData()->value(key)) {
                            m_db->metadata()->customData()->set(key, newValue);
                            break;
                        }
                    }
                }
            }

            updateModel();
        }
    }
}

// Updates the shared key list after the list is cleared
void DatabaseSettingsWidgetBrowser::updateSharedKeyList()
{
    updateModel();
}

void DatabaseSettingsWidgetBrowser::clientRestrictionOptionChanged()
{
    databaseSettings()->setClientRestrictions(m_db, m_ui->clientRestrictionsCheckbox->isChecked());
    updateAllowedProcessesModel();
}
