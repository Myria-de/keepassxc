/**
 ***************************************************************************
 * @file BrowserService.cpp
 *
 * @brief
 *
 * Copyright (C) 2013
 *
 * @author	        Francois Ferrand
 * @date	        4/2013
 * @modifications   (C) 2017 Sami Vänttinen
 ***************************************************************************
 */

#include <QInputDialog>
#include <QMessageBox>
#include "BrowserService.h"
#include "BrowserSettings.h"
#include "BrowserAccessControlDialog.h"
#include "core/Database.h"
#include "core/Entry.h"
#include "core/Group.h"
#include "core/EntrySearcher.h"
#include "core/Metadata.h"
#include "core/Uuid.h"
#include "core/PasswordGenerator.h"

// de887cc3-0363-43b8-974b-5911b8816224
static const unsigned char KEEPASSBROWSER_UUID_DATA[] = {
    0xde, 0x88, 0x7c, 0xc3, 0x03, 0x63, 0x43, 0xb8,
    0x97, 0x4b, 0x59, 0x11, 0xb8, 0x81, 0x62, 0x24
};
static const Uuid KEEPASSBROWSER_UUID = Uuid(QByteArray::fromRawData(reinterpret_cast<const char *>(KEEPASSBROWSER_UUID_DATA), sizeof(KEEPASSBROWSER_UUID_DATA)));
static const char KEEPASSBROWSER_NAME[] = "chromeKeePassXC Settings";
static const char ASSOCIATE_KEY_PREFIX[] = "Public Key: ";
static const char KEEPASSBROWSER_GROUP_NAME[] = "chromeKeePassXC Passwords";
static int        KEEPASSBROWSER_DEFAULT_ICON = 1;

BrowserService::BrowserService(DatabaseTabWidget* parent) : m_dbTabWidget(parent)
{

}

bool BrowserService::isDatabaseOpened() const
{
    if (DatabaseWidget* dbWidget = m_dbTabWidget->currentDatabaseWidget())
        switch(dbWidget->currentMode()) {
        case DatabaseWidget::None:
        case DatabaseWidget::LockedMode:
            break;

        case DatabaseWidget::ViewMode:
        case DatabaseWidget::EditMode:
            return true;
        }
    return false;
}

bool BrowserService::openDatabase()
{
    if (!BrowserSettings::unlockDatabase())
        return false;
    if (DatabaseWidget * dbWidget = m_dbTabWidget->currentDatabaseWidget()) {
        switch(dbWidget->currentMode()) {
        case DatabaseWidget::None:
        case DatabaseWidget::LockedMode:
            break;

        case DatabaseWidget::ViewMode:
        case DatabaseWidget::EditMode:
            return true;
        }
    }
    m_dbTabWidget->activateWindow();
    return false;
}

QString BrowserService::getDatabaseRootUuid()
{
    if (DatabaseWidget* dbWidget = m_dbTabWidget->currentDatabaseWidget())
        if (Database* db = dbWidget->database())
            if (Group* rootGroup = db->rootGroup())
                return rootGroup->uuid().toHex();
    return QString();
}

QString BrowserService::getDatabaseRecycleBinUuid()
{
    if (DatabaseWidget* dbWidget = m_dbTabWidget->currentDatabaseWidget())
        if (Database* db = dbWidget->database())
            if (Group* recycleBin = db->metadata()->recycleBin())
                return recycleBin->uuid().toHex();
    return QString();
}

Entry* BrowserService::getConfigEntry(bool create)
{
    if (DatabaseWidget * dbWidget = m_dbTabWidget->currentDatabaseWidget())
        if (Database * db = dbWidget->database()) {
            Entry* entry = db->resolveEntry(KEEPASSBROWSER_UUID);
            if (!entry && create) {
                entry = new Entry();
                entry->setTitle(QLatin1String(KEEPASSBROWSER_NAME));
                entry->setUuid(KEEPASSBROWSER_UUID);
                entry->setAutoTypeEnabled(false);
                entry->setGroup(db->rootGroup());
            } else if (entry && entry->group() == db->metadata()->recycleBin()) {
                if (create)
                    entry->setGroup(db->rootGroup());
                else
                    entry = NULL;
            }
            return entry;
        }
    return NULL;
}

QString BrowserService::storeKey(const QString &key)
{
    QString id;
    if (Entry* config = getConfigEntry(true)) {

        //ShowNotification("New key association requested")

        do {
            bool ok;
            //Indicate who wants to associate, and request user to enter the 'name' of association key
            id = QInputDialog::getText(0,
                    tr("KeePassXC: New key association request"),
                    tr("You have received an association "
                       "request for the above key.\n"
                       "If you would like to allow it access "
                       "to your KeePassXC database\n"
                       "give it a unique name to identify and accept it."),
                    QLineEdit::Normal, QString(), &ok);
            if (!ok || id.isEmpty())
                return QString();

            //Warn if association key already exists
        } while(config->attributes()->contains(QLatin1String(ASSOCIATE_KEY_PREFIX) + id) &&
                QMessageBox::warning(0, tr("KeePassXC: Overwrite existing key?"),
                                     tr("A shared encryption-key with the name \"%1\" already exists.\nDo you want to overwrite it?").arg(id),
                                     QMessageBox::Yes | QMessageBox::No) == QMessageBox::No);

        config->attributes()->set(QLatin1String(ASSOCIATE_KEY_PREFIX) + id, key, true);
    }
    return id;
}

QString BrowserService::getKey(const QString &id)
{
    if (Entry* config = getConfigEntry())
        return config->attributes()->value(QLatin1String(ASSOCIATE_KEY_PREFIX) + id);
    return QString();
}