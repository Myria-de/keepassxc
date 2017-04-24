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

#include <QJsonArray>
#include <QInputDialog>
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

// No need to use KeepassHttpProtocol. Just return a JSON array.
QJsonArray BrowserService::findMatchingEntries(const QString& /*id*/, const QString& url, const QString& submitUrl, const QString& realm)
{
    const bool alwaysAllowAccess = BrowserSettings::alwaysAllowAccess();
    const QString host = QUrl(url).host();
    const QString submitHost = QUrl(submitUrl).host();

    //Check entries for authorization
    QList<Entry*> pwEntriesToConfirm;
    QList<Entry*> pwEntries;
    //Q_FOREACH (QJsonObject entry, searchEntries(url)) {
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
    }

    //If unsure, ask user for confirmation
    //if (!pwEntriesToConfirm.isEmpty()
    //    && HttpSettings::showNotification()
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
            //Q_FOREACH (QJsonObject entry, pwEntriesToConfirm) {
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
        //Q_FOREACH (const QJsonObject entry, pwEntries)
        for (const Entry* entry : pwEntries)
            priorities.insert(entry, sortPriority(entry, host, submitUrl, baseSubmitURL));

        //Sort by priorities
        qSort(pwEntries.begin(), pwEntries.end(), SortEntries(priorities, BrowserSettings::sortByTitle() ? "Title" : "UserName"));
    }

    //if (pwEntries.count() > 0)
    //{
    //    var names = (from e in resp.Entries select e.Name).Distinct<string>();
    //    var n = String.Join("\n    ", names.ToArray<string>());
    //    if (HttpSettings::receiveCredentialNotification())
    //        ShowNotification(QString("%0: %1 is receiving credentials for:\n%2").arg(Id).arg(host).arg(n)));
    //}

    //Fill the list
    /*QList<KeepassHttpProtocol::Entry> result;
    result.reserve(pwEntries.count());
    Q_FOREACH (Entry * entry, pwEntries)
        result << prepareEntry(entry);*/
    
    // Fill the list
    QJsonArray result;
    //Q_FOREACH (QJsonObject user, pwEntries)
    for (Entry* entry : pwEntries)
        result << prepareEntry(entry);

    return result;
}

QList<Entry*> BrowserService::searchEntries(Database* db, const QString& hostname)
{
    QList<Entry*> entries;
    if (Group* rootGroup = db->rootGroup())
        //Q_FOREACH (Entry* entry, EntrySearcher().search(hostname, rootGroup, Qt::CaseInsensitive)) {
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
        //Q_FOREACH (Database* db, databases)
        for (Database* db : databases)
            entries << searchEntries(db, hostname);
    } while(entries.isEmpty() && removeFirstDomain(hostname));

    return entries;
}

QJsonObject BrowserService::prepareEntry(const Entry* entry)
{
    QJsonObject res;
    res["login"] = entry->username();
    res["password"] = entry->password();
    res["name"] = entry->title();
    res["uuid"] = entry->uuid().toHex();

    /*
    if (BrowserSettings::supportKphFields()) {
        const EntryAttributes * attr = entry->attributes();
        //Q_FOREACH (const QString& key, attr->keys())
        for (const QString& key : attr->keys())
            if (key.startsWith(QLatin1String("KPH: ")))
                res.addStringField(key, attr->value(key));
    }
    */
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