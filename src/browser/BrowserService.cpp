/**
 ***************************************************************************
 * @file BrowserService.cpp
 *
 * @brief
 *
 * Copyright (C) 2013
 *
 * @author	        (C) 2013 Francois Ferrand
 * @modifications   (C) 2017 Sami Vänttinen
 ***************************************************************************
 */

#include <QJsonArray>
#include <QInputDialog>
#include <QProgressDialog>
#include <QMessageBox>
#include "BrowserService.h"
#include "BrowserSettings.h"
#include "BrowserEntryConfig.h"
#include "BrowserAccessControlDialog.h"
#include "core/Database.h"
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
        default:
            break;
    return false;
}

bool BrowserService::openDatabase()
{
    if (!BrowserSettings::unlockDatabase())
        return false;
    if (DatabaseWidget* dbWidget = m_dbTabWidget->currentDatabaseWidget()) {
        switch(dbWidget->currentMode()) {
        case DatabaseWidget::None:
        case DatabaseWidget::LockedMode:
            break;

        case DatabaseWidget::ViewMode:
        case DatabaseWidget::EditMode:
            return true;
        }
        default:
            break;
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
    if (DatabaseWidget* dbWidget = m_dbTabWidget->currentDatabaseWidget())
        if (Database* db = dbWidget->database()) {
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

    if (thread()!=QThread::currentThread())
    {
        QMetaObject::invokeMethod(this, "storeKey", Qt::BlockingQueuedConnection, Q_RETURN_ARG(QString, id), Q_ARG(QString, key));
        return id;
    }

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

// No need to use KeepassHttpProtocol. Just return a JSON array.
QJsonArray BrowserService::findMatchingEntries(const QString& id, const QString& url, const QString& submitUrl, const QString& realm)
{
    QJsonArray result;
    if (thread()!=QThread::currentThread())
    {
        QMetaObject::invokeMethod(this, "findMatchingEntries", Qt::BlockingQueuedConnection, Q_RETURN_ARG(QJsonArray, result),
                                                                                            Q_ARG(const QString&, id),
                                                                                            Q_ARG(const QString&, url),
                                                                                            Q_ARG(const QString&, submitUrl),
                                                                                            Q_ARG(const QString&, realm));
        return result;
    }

    const bool alwaysAllowAccess = BrowserSettings::alwaysAllowAccess();
    const QString host = QUrl(url).host();
    const QString submitHost = QUrl(submitUrl).host();

    //Check entries for authorization
    QList<Entry*> pwEntriesToConfirm;
    QList<Entry*> pwEntries;
    for (Entry* entry : searchEntries(url)) {
        switch (checkAccess(entry, host, submitHost, realm)) {
        case Denied:
            continue;

        case Unknown:
            if (alwaysAllowAccess)
                pwEntries.append(entry);
            else
                pwEntriesToConfirm.append(entry);
            break;

        case Allowed:
            pwEntries.append(entry);
            break;
        }
        default:
            break;
    }

    //If unsure, ask user for confirmation
    //if (!pwEntriesToConfirm.isEmpty()
    //    && BrowserSettings::showNotification()
    //    && !ShowNotification(QString("%0: %1 is requesting access, click to allow or deny")
    //                                 .arg(id).arg(submitHost.isEmpty() ? host : submithost));
    //    pwEntriesToConfirm.clear(); //timeout --> do not request confirmation

    if (!pwEntriesToConfirm.isEmpty()) {
        BrowserAccessControlDialog dlg;
        dlg.setUrl(url);
        dlg.setItems(pwEntriesToConfirm);
        //dlg.setRemember();        //TODO: setting!

        int res = dlg.exec();
        if (dlg.remember()) {
            for (Entry* entry : pwEntriesToConfirm) {
                BrowserEntryConfig config;
                config.load(entry);
                if (res == QDialog::Accepted) {
                    config.allow(host);
                    if (!submitHost.isEmpty() && host != submitHost)
                        config.allow(submitHost);
                } else if (res == QDialog::Rejected) {
                    config.deny(host);
                    if (!submitHost.isEmpty() && host != submitHost)
                        config.deny(submitHost);
                }
                if (!realm.isEmpty())
                    config.setRealm(realm);
                config.save(entry);
            }
        }
        if (res == QDialog::Accepted)
            pwEntries.append(pwEntriesToConfirm);
    }

    //Sort results
    const bool sortSelection = true;
    if (sortSelection) {
        QUrl url(submitUrl);
        if (url.scheme().isEmpty())
            url.setScheme("http");
        const QString submitUrl = url.toString(QUrl::StripTrailingSlash);
        const QString baseSubmitURL = url.toString(QUrl::StripTrailingSlash | QUrl::RemovePath | QUrl::RemoveQuery | QUrl::RemoveFragment);

        //Cache priorities
        QHash<const Entry*, int> priorities;
        priorities.reserve(pwEntries.size());
        for (const Entry* entry : pwEntries)
            priorities.insert(entry, sortPriority(entry, host, submitUrl, baseSubmitURL));

        //Sort by priorities
        qSort(pwEntries.begin(), pwEntries.end(), SortEntries(priorities, BrowserSettings::sortByTitle() ? "Title" : "UserName"));
    }

    //if (pwEntries.count() > 0)
    //{
    //    var names = (from e in resp.Entries select e.Name).Distinct<string>();
    //    var n = String.Join("\n    ", names.ToArray<string>());
    //    if (BrowserSettings::receiveCredentialNotification())
    //        ShowNotification(QString("%0: %1 is receiving credentials for:\n%2").arg(Id).arg(host).arg(n)));
    //}

    // Fill the list
    //QJsonArray result;
    for (Entry* entry : pwEntries)
        result << prepareEntry(entry);

    return result;
}

void BrowserService::addEntry(const QString &, const QString &login, const QString &password, const QString &url, const QString &submitUrl, const QString &realm)
{
    if (Group* group = findCreateAddEntryGroup()) {
        Entry* entry = new Entry();
        entry->setUuid(Uuid::random());
        entry->setTitle(QUrl(url).host());
        entry->setUrl(url);
        entry->setIcon(KEEPASSBROWSER_DEFAULT_ICON);
        entry->setUsername(login);
        entry->setPassword(password);
        entry->setGroup(group);

        const QString host = QUrl(url).host();
        const QString submitHost = QUrl(submitUrl).host();
        BrowserEntryConfig config;
        config.allow(host);
        if (!submitHost.isEmpty())
            config.allow(submitHost);
        if (!realm.isEmpty())
            config.setRealm(realm);
        config.save(entry);
    }
}

void BrowserService::updateEntry(const QString &, const QString &uuid, const QString &login, const QString &password, const QString &url)
{
    if (thread()!=QThread::currentThread())
    {
        QMetaObject::invokeMethod(this, "updateEntry", Qt::BlockingQueuedConnection);
    }

    if (DatabaseWidget* dbWidget = m_dbTabWidget->currentDatabaseWidget())
        if (Database* db = dbWidget->database())
            if (Entry* entry = db->resolveEntry(Uuid::fromHex(uuid))) {
                QString u = entry->username();
                if (u != login || entry->password() != password) {
                    //ShowNotification(QString("%0: You have an entry change prompt waiting, click to activate").arg(requestId));
                    if (BrowserSettings::alwaysAllowUpdate()
                        || QMessageBox::warning(0, tr("KeePassXC: Update Entry"),
                                                tr("Do you want to update the information in %1 - %2?")
                                                .arg(QUrl(url).host().toHtmlEscaped()).arg(u.toHtmlEscaped()),
                                                QMessageBox::Yes|QMessageBox::No) == QMessageBox::Yes ) {
                        entry->beginUpdate();
                        entry->setUsername(login);
                        entry->setPassword(password);
                        entry->endUpdate();
                    }
                }
            }
}

QList<Entry*> BrowserService::searchEntries(Database* db, const QString& hostname)
{
    QList<Entry*> entries;
    if (Group* rootGroup = db->rootGroup())
        for (Entry* entry : EntrySearcher().search(hostname, rootGroup, Qt::CaseInsensitive)) {
            QString title = entry->title();
            QString url = entry->url();

            //Filter to match hostname in Title and Url fields
            if ((!title.isEmpty() && hostname.contains(title))
                || (!url.isEmpty() && hostname.contains(url))
                || (matchUrlScheme(title) && hostname.endsWith(QUrl(title).host()))
                || (matchUrlScheme(url) && hostname.endsWith(QUrl(url).host())) )
                entries.append(entry);
        }
    return entries;
}

QList<Entry*> BrowserService::searchEntries(const QString& text)
{
    //Get the list of databases to search
    QList<Database*> databases;
    if (BrowserSettings::searchInAllDatabases()) {
        for (int i = 0; i < m_dbTabWidget->count(); i++)
            if (DatabaseWidget* dbWidget = qobject_cast<DatabaseWidget*>(m_dbTabWidget->widget(i)))
                if (Database* db = dbWidget->database())
                    databases << db;
    }
    else if (DatabaseWidget* dbWidget = m_dbTabWidget->currentDatabaseWidget()) {
        if (Database* db = dbWidget->database())
            databases << db;
    }

    //Search entries matching the hostname
    QString hostname = QUrl(text).host();
    QList<Entry*> entries;
    do {
        for (Database* db : databases)
            entries << searchEntries(db, hostname);
    } while(entries.isEmpty() && removeFirstDomain(hostname));

    return entries;
}

void BrowserService::removeSharedEncryptionKeys()
{
    if (!isDatabaseOpened()) {
        QMessageBox::critical(0, tr("KeePassXC: Database locked!"),
                              tr("The active database is locked!\n"
                                 "Please unlock the selected database or choose another one which is unlocked."),
                              QMessageBox::Ok);
    } else if (Entry* entry = getConfigEntry()) {
        QStringList keysToRemove;
        for (const QString& key : entry->attributes()->keys())
            if (key.startsWith(ASSOCIATE_KEY_PREFIX))
                keysToRemove << key;

        if(keysToRemove.count()) {
            entry->beginUpdate();
            for (const QString& key : keysToRemove)
                entry->attributes()->remove(key);
            entry->endUpdate();

            const int count = keysToRemove.count();
            QMessageBox::information(0, tr("KeePassXC: Removed keys from database"),
                                     tr("Successfully removed %1 encryption-%2 from KeePassXC Settings.").arg(count).arg(count ? "keys" : "key"),
                                     QMessageBox::Ok);
        } else {
            QMessageBox::information(0, tr("KeePassXC: No keys found"),
                                     tr("No shared encryption-keys found in KeePassXC Settings."),
                                     QMessageBox::Ok);
        }
    } else {
        QMessageBox::information(0, tr("KeePassXC: Settings not available!"),
                                 tr("The active database does not contain an entry of KeePassXC Settings."),
                                 QMessageBox::Ok);
    }
}

void BrowserService::removeStoredPermissions()
{
    if (!isDatabaseOpened()) {
        QMessageBox::critical(0, tr("KeePassXC: Database locked!"),
                              tr("The active database is locked!\n"
                                 "Please unlock the selected database or choose another one which is unlocked."),
                              QMessageBox::Ok);
    } else {
        Database* db = m_dbTabWidget->currentDatabaseWidget()->database();
        QList<Entry*> entries = db->rootGroup()->entriesRecursive();

        QProgressDialog progress(tr("Removing stored permissions..."), tr("Abort"), 0, entries.count());
        progress.setWindowModality(Qt::WindowModal);

        uint counter = 0;
        for (Entry* entry : entries) {
            if (progress.wasCanceled())
                return;
            if (entry->attributes()->contains(KEEPASSBROWSER_NAME)) {
                entry->beginUpdate();
                entry->attributes()->remove(KEEPASSBROWSER_NAME);
                entry->endUpdate();
                counter ++;
            }
            progress.setValue(progress.value() + 1);
        }
        progress.reset();

        if (counter > 0) {
            QMessageBox::information(0, tr("KeePassXC: Removed permissions"),
                                     tr("Successfully removed permissions from %1 %2.").arg(counter).arg(counter ? "entries" : "entry"),
                                     QMessageBox::Ok);
        } else {
            QMessageBox::information(0, tr("KeePassXC: No entry with permissions found!"),
                                     tr("The active database does not contain an entry with permissions."),
                                     QMessageBox::Ok);
        }
    }
}

QJsonObject BrowserService::prepareEntry(const Entry* entry)
{
    QJsonObject res;
    res["login"] = entry->username();
    res["password"] = entry->password();
    res["name"] = entry->title();
    res["uuid"] = entry->uuid().toHex();

    if (BrowserSettings::supportKphFields()) {
        const EntryAttributes* attr = entry->attributes();
        QJsonArray stringFields;
        for (const QString& key : attr->keys()) {
            if (key.startsWith(QLatin1String("KPH: "))) {
                QJsonObject sField;
                sField[key] = attr->value(key);
                stringFields << sField;
            }
        }
        res["stringFields"] = stringFields;
    }
    return res;
}

BrowserService::Access BrowserService::checkAccess(const Entry *entry, const QString & host, const QString & submitHost, const QString & realm)
{
    BrowserEntryConfig config;
    if (!config.load(entry))
        return Unknown;  //not configured
    if ((config.isAllowed(host)) && (submitHost.isEmpty() || config.isAllowed(submitHost)))
        return Allowed;  //allowed
    if ((config.isDenied(host)) || (!submitHost.isEmpty() && config.isDenied(submitHost)))
        return Denied;   //denied
    if (!realm.isEmpty() && config.realm() != realm)
        return Denied;
    return Unknown;      //not configured for this host
}

Group* BrowserService::findCreateAddEntryGroup()
{
    if (DatabaseWidget* dbWidget = m_dbTabWidget->currentDatabaseWidget())
        if (Database* db = dbWidget->database())
            if (Group* rootGroup = db->rootGroup()) {
                const QString groupName = QLatin1String(KEEPASSBROWSER_GROUP_NAME); //TODO: setting to decide where new keys are created

                for (const Group* g : rootGroup->groupsRecursive(true))
                    if (g->name() == groupName)
                        return db->resolveGroup(g->uuid());

                Group* group;
                group = new Group();
                group->setUuid(Uuid::random());
                group->setName(groupName);
                group->setIcon(KEEPASSBROWSER_DEFAULT_ICON);
                group->setParent(rootGroup);
                return group;
            }
    return NULL;
}

int BrowserService::sortPriority(const Entry* entry, const QString& host, const QString& submitUrl, const QString& baseSubmitUrl) const
{
    QUrl url(entry->url());
    if (url.scheme().isEmpty())
        url.setScheme("http");
    const QString entryURL = url.toString(QUrl::StripTrailingSlash);
    const QString baseEntryURL = url.toString(QUrl::StripTrailingSlash | QUrl::RemovePath | QUrl::RemoveQuery | QUrl::RemoveFragment);

    if (submitUrl == entryURL)
        return 100;
    if (submitUrl.startsWith(entryURL) && entryURL != host && baseSubmitUrl != entryURL)
        return 90;
    if (submitUrl.startsWith(baseEntryURL) && entryURL != host && baseSubmitUrl != baseEntryURL)
        return 80;
    if (entryURL == host)
        return 70;
    if (entryURL == baseSubmitUrl)
        return 60;
    if (entryURL.startsWith(submitUrl))
        return 50;
    if (entryURL.startsWith(baseSubmitUrl) && baseSubmitUrl != host)
        return 40;
    if (submitUrl.startsWith(entryURL))
        return 30;
    if (submitUrl.startsWith(baseEntryURL))
        return 20;
    if (entryURL.startsWith(host))
        return 10;
    if (host.startsWith(entryURL))
        return 5;
    return 0;
}

bool BrowserService::matchUrlScheme(const QString & url)
{
    QString str = url.left(8).toLower();
    return str.startsWith("http://") ||
           str.startsWith("https://") ||
           str.startsWith("ftp://") ||
           str.startsWith("ftps://");
}

bool BrowserService::removeFirstDomain(QString & hostname)
{
    int pos = hostname.indexOf(".");
    if (pos < 0)
        return false;
    hostname = hostname.mid(pos + 1);
    return !hostname.isEmpty();
}
