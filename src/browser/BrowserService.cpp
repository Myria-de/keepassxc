/*
*  Copyright (C) 2013 Francois Ferrand
*  Copyright (C) 2017 Sami Vänttinen <sami.vanttinen@protonmail.com>
*  Copyright (C) 2017 KeePassXC Team <team@keepassxc.org>
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

#include <QJsonArray>
#include <QInputDialog>
#include <QProgressDialog>
#include <QMessageBox>
#include <QRegularExpression>
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
static const unsigned char KEEPASSXCBROWSER_UUID_DATA[] = {
    0xde, 0x88, 0x7c, 0xc3, 0x03, 0x63, 0x43, 0xb8,
    0x97, 0x4b, 0x59, 0x11, 0xb8, 0x81, 0x62, 0x24
};
static const Uuid KEEPASSXCBROWSER_UUID = Uuid(QByteArray::fromRawData(reinterpret_cast<const char *>(KEEPASSXCBROWSER_UUID_DATA), sizeof(KEEPASSXCBROWSER_UUID_DATA)));
static const char KEEPASSXCBROWSER_NAME[] = "keepassxc-browser Settings";
static const char ASSOCIATE_KEY_PREFIX[] = "Public Key: ";
static const char KEEPASSXCBROWSER_GROUP_NAME[] = "keepassxc-browser Passwords";
static int        KEEPASSXCBROWSER_DEFAULT_ICON = 1;

BrowserService::BrowserService(DatabaseTabWidget* parent) :
    m_dbTabWidget(parent),
    m_dialogActive(false)
{
    connect(m_dbTabWidget, SIGNAL(databaseLocked(DatabaseWidget*)), this, SLOT(databaseLocked(DatabaseWidget*)));
    connect(m_dbTabWidget, SIGNAL(databaseUnlocked(DatabaseWidget*)), this, SLOT(databaseUnlocked(DatabaseWidget*)));
    connect(m_dbTabWidget, SIGNAL(activateDatabaseChanged(DatabaseWidget*)), this, SLOT(activateDatabaseChanged(DatabaseWidget*)));
}

bool BrowserService::isDatabaseOpened() const
{
    DatabaseWidget* dbWidget = m_dbTabWidget->currentDatabaseWidget();
    if (!dbWidget) {
        return false;
    }

    if (dbWidget->currentMode() == DatabaseWidget::ViewMode || dbWidget->currentMode() == DatabaseWidget::EditMode) {
        return true;
    }

    return false;
}

bool BrowserService::openDatabase()
{
    if (!BrowserSettings::unlockDatabase()) {
        return false;
    }

    DatabaseWidget* dbWidget = m_dbTabWidget->currentDatabaseWidget();
    if (!dbWidget) {
        return false;
    }

    if (dbWidget->currentMode() == DatabaseWidget::ViewMode || dbWidget->currentMode() == DatabaseWidget::EditMode) {
        return true;
    }

    m_dbTabWidget->activateWindow();
    return false;
}

void BrowserService::lockDatabase()
{
    if (thread() != QThread::currentThread()) {
        QMetaObject::invokeMethod(this, "lockDatabase", Qt::BlockingQueuedConnection);
    }

    DatabaseWidget* dbWidget = m_dbTabWidget->currentDatabaseWidget();
    if (!dbWidget) {
        return;
    }

    if (dbWidget->currentMode() == DatabaseWidget::ViewMode || dbWidget->currentMode() == DatabaseWidget::EditMode) {
        dbWidget->lock();
    }
}

QString BrowserService::getDatabaseRootUuid()
{
    Database* db = getDatabase();
    if (!db) {
        return QString();
    }

    Group* rootGroup = db->rootGroup();
    if (!rootGroup) {
        return QString();
    }

    return rootGroup->uuid().toHex();
}

QString BrowserService::getDatabaseRecycleBinUuid()
{
    Database* db = getDatabase();
    if (!db) {
        return QString();
    }

    Group* recycleBin = db->metadata()->recycleBin();
    if (!recycleBin) {
        return QString();
    }
    return recycleBin->uuid().toHex();
}

Entry* BrowserService::getConfigEntry(bool create)
{
    Entry* entry = nullptr;
    Database* db = getDatabase();
    if (!db) {
        return nullptr;
    }

    entry = db->resolveEntry(KEEPASSXCBROWSER_UUID);
    if (!entry && create) {
        entry = new Entry();
        entry->setTitle(QLatin1String(KEEPASSXCBROWSER_NAME));
        entry->setUuid(KEEPASSXCBROWSER_UUID);
        entry->setAutoTypeEnabled(false);
        entry->setGroup(db->rootGroup());
        return entry;
    }

    if (entry && entry->group() == db->metadata()->recycleBin()) {
        if (!create) {
            return nullptr;
        } else {
            entry->setGroup(db->rootGroup());
            return entry;
        }
    }

    return entry;
}

QString BrowserService::storeKey(const QString& key)
{
    QString id;

    if (thread() != QThread::currentThread()) {
        QMetaObject::invokeMethod(this, "storeKey", Qt::BlockingQueuedConnection,
                                  Q_RETURN_ARG(QString, id),
                                  Q_ARG(const QString&, key));
        return id;
    }

    Entry* config = getConfigEntry(true);
    if (!config) {
        return QString();
    }

    bool contains = false;
    QMessageBox::StandardButton dialogResult = QMessageBox::No;

    do {
        bool ok = false;
        id = QInputDialog::getText(0, tr("KeePassXC: New key association request"),
                                   tr("You have received an association "
                                      "request for the above key.\n"
                                      "If you would like to allow it access "
                                      "to your KeePassXC database,\n"
                                      "give it a unique name to identify and accept it."),
                                    QLineEdit::Normal, QString(), &ok);
        if (!ok || id.isEmpty()) {
            return QString();
        }

        contains = config->attributes()->contains(QLatin1String(ASSOCIATE_KEY_PREFIX) + id);
        dialogResult = QMessageBox::warning(0, tr("KeePassXC: Overwrite existing key?"),
                                                 tr("A shared encryption-key with the name \"%1\" already exists.\nDo you want to overwrite it?").arg(id),
                                                 QMessageBox::Yes | QMessageBox::No);
    } while (contains && dialogResult == QMessageBox::No);

    config->attributes()->set(QLatin1String(ASSOCIATE_KEY_PREFIX) + id, key, true);
    return id;
}

QString BrowserService::getKey(const QString& id)
{
    Entry* config = getConfigEntry();
    if (!config) {
        return QString();
    }

    return config->attributes()->value(QLatin1String(ASSOCIATE_KEY_PREFIX) + id);
}

// No need to use KeepassHttpProtocol. Just return a JSON array.
QJsonArray BrowserService::findMatchingEntries(const QString& id, const QString& url, const QString& submitUrl, const QString& realm)
{
    QJsonArray result;
    if (thread() != QThread::currentThread()) {
        QMetaObject::invokeMethod(this, "findMatchingEntries", Qt::BlockingQueuedConnection,
                                  Q_RETURN_ARG(QJsonArray, result),
                                  Q_ARG(const QString&, id),
                                  Q_ARG(const QString&, url),
                                  Q_ARG(const QString&, submitUrl),
                                  Q_ARG(const QString&, realm));
        return result;
    }

    const bool alwaysAllowAccess = BrowserSettings::alwaysAllowAccess();
    const QString host = QUrl(url).host();
    const QString submitHost = QUrl(submitUrl).host();

    // Check entries for authorization
    QList<Entry*> pwEntriesToConfirm;
    QList<Entry*> pwEntries;
    for (Entry* entry : searchEntries(url)) {
        switch (checkAccess(entry, host, submitHost, realm)) {
        case Denied:
            continue;

        case Unknown:
            if (alwaysAllowAccess) {
                pwEntries.append(entry);
            } else {
                pwEntriesToConfirm.append(entry);
            }
            break;

        case Allowed:
            pwEntries.append(entry);
            break;
        }
    }

    // Confirm entries
    if (confirmEntries(pwEntriesToConfirm, url, host, submitHost, realm)) {
        pwEntries.append(pwEntriesToConfirm);
    }

    if (pwEntries.isEmpty()) {
        return QJsonArray();
    }

    // Sort results
    pwEntries = sortEntries(pwEntries, host, submitUrl);

    // Fill the list
    for (Entry* entry : pwEntries) {
        result << prepareEntry(entry);
    }

    return result;
}

void BrowserService::addEntry(const QString&, const QString& login, const QString& password, const QString& url, const QString& submitUrl, const QString& realm)
{
    Group* group = findCreateAddEntryGroup();
    if (!group) {
        return;
    }

    Entry* entry = new Entry();
    entry->setUuid(Uuid::random());
    entry->setTitle(QUrl(url).host());
    entry->setUrl(url);
    entry->setIcon(KEEPASSXCBROWSER_DEFAULT_ICON);
    entry->setUsername(login);
    entry->setPassword(password);
    entry->setGroup(group);

    const QString host = QUrl(url).host();
    const QString submitHost = QUrl(submitUrl).host();
    BrowserEntryConfig config;
    config.allow(host);

    if (!submitHost.isEmpty()) {
        config.allow(submitHost);
    }
    if (!realm.isEmpty()) {
        config.setRealm(realm);
    }
    config.save(entry);
}

void BrowserService::updateEntry(const QString& id, const QString& uuid, const QString& login, const QString& password, const QString& url)
{
    if (thread() != QThread::currentThread()) {
        QMetaObject::invokeMethod(this, "updateEntry", Qt::BlockingQueuedConnection,
                                  Q_ARG(const QString&, id),
                                  Q_ARG(const QString&, uuid),
                                  Q_ARG(const QString&, login),
                                  Q_ARG(const QString&, password),
                                  Q_ARG(const QString&, url));
    }

    Database* db = getDatabase();
    if (!db) {
        return;
    }

    Entry* entry = db->resolveEntry(Uuid::fromHex(uuid));
    if (!entry) {
        return;
    }

    QString username = entry->username();
    if (username.isEmpty()) {
        return;
    }

    if (username.compare(login, Qt::CaseSensitive) != 0 || entry->password().compare(password, Qt::CaseSensitive) != 0) {
        QMessageBox::StandardButton dialogResult = QMessageBox::No;
        if (!BrowserSettings::alwaysAllowUpdate()) {
            dialogResult = QMessageBox::warning(0, tr("KeePassXC: Update Entry"),
                                                tr("Do you want to update the information in %1 - %2?")
                                                .arg(QUrl(url).host()).arg(username),
                                                QMessageBox::Yes|QMessageBox::No);
        }

        if (BrowserSettings::alwaysAllowUpdate() || dialogResult == QMessageBox::Yes) {
            entry->beginUpdate();
            entry->setUsername(login);
            entry->setPassword(password);
            entry->endUpdate();
        }
    }
}

QList<Entry*> BrowserService::searchEntries(Database* db, const QString& hostname)
{
    QList<Entry*> entries;
    Group* rootGroup = db->rootGroup();
    if (!rootGroup) {
        return entries;
    }

    for (Entry* entry : EntrySearcher().search(hostname, rootGroup, Qt::CaseInsensitive)) {
        QString title = entry->title();
        QString url = entry->url();

        // Filter to match hostname in Title and Url fields
        if ((!title.isEmpty() && hostname.contains(title))
            || (!url.isEmpty() && hostname.contains(url))
            || (matchUrlScheme(title) && hostname.endsWith(QUrl(title).host()))
            || (matchUrlScheme(url) && hostname.endsWith(QUrl(url).host())) ) {
                entries.append(entry);
        }
    }

    return entries;
}

QList<Entry*> BrowserService::searchEntries(const QString& text)
{
    // Get the list of databases to search
    QList<Database*> databases;
    if (BrowserSettings::searchInAllDatabases()) {
        const int count = m_dbTabWidget->count();
        for (int i = 0; i < count; ++i) {
            if (DatabaseWidget* dbWidget = qobject_cast<DatabaseWidget*>(m_dbTabWidget->widget(i))) {
                if (Database* db = dbWidget->database()) {
                    databases << db;
                }
            }
        }
    } else if (Database* db = getDatabase()) {
        databases << db;
    }

    // Search entries matching the hostname
    QString hostname = QUrl(text).host();
    QList<Entry*> entries;
    do {
        for (Database* db : databases) {
            entries << searchEntries(db, hostname);
        }
    } while (entries.isEmpty() && removeFirstDomain(hostname));

    return entries;
}

void BrowserService::removeSharedEncryptionKeys()
{
    if (!isDatabaseOpened()) {
        QMessageBox::critical(0, tr("KeePassXC: Database locked!"),
                              tr("The active database is locked!\n"
                                 "Please unlock the selected database or choose another one which is unlocked."),
                              QMessageBox::Ok);
        return;
    }

    Entry* entry = getConfigEntry();
    if (!entry) {
        QMessageBox::information(0, tr("KeePassXC: Settings not available!"),
                                 tr("The active database does not contain a settings entry."),
                                 QMessageBox::Ok);
        return;
    }

    QStringList keysToRemove;
    for (const QString& key : entry->attributes()->keys()) {
        if (key.startsWith(ASSOCIATE_KEY_PREFIX)) {
            keysToRemove << key;
        }
    }

    if (keysToRemove.isEmpty()) {
        QMessageBox::information(0, tr("KeePassXC: No keys found"),
                                 tr("No shared encryption keys found in KeePassXC Settings."),
                                 QMessageBox::Ok);
        return;
    }

    entry->beginUpdate();
    for (const QString& key : keysToRemove) {
        entry->attributes()->remove(key);
    }
    entry->endUpdate();

    const int count = keysToRemove.count();
    QMessageBox::information(0, tr("KeePassXC: Removed keys from database"),
                             tr("Successfully removed %n encryption key(s) from KeePassXC settings.", "", count),
                             QMessageBox::Ok);

}

void BrowserService::removeStoredPermissions()
{
    if (!isDatabaseOpened()) {
        QMessageBox::critical(0, tr("KeePassXC: Database locked!"),
                              tr("The active database is locked!\n"
                                 "Please unlock the selected database or choose another one which is unlocked."),
                              QMessageBox::Ok);
        return;
    }

    Database* db = m_dbTabWidget->currentDatabaseWidget()->database();
    if (!db) {
        return;
    }

    QList<Entry*> entries = db->rootGroup()->entriesRecursive();

    QProgressDialog progress(tr("Removing stored permissions…"), tr("Abort"), 0, entries.count());
    progress.setWindowModality(Qt::WindowModal);

    uint counter = 0;
    for (Entry* entry : entries) {
        if (progress.wasCanceled()) {
            return;
        }

        if (entry->attributes()->contains(KEEPASSXCBROWSER_NAME)) {
            entry->beginUpdate();
            entry->attributes()->remove(KEEPASSXCBROWSER_NAME);
            entry->endUpdate();
            ++counter;
        }
        progress.setValue(progress.value() + 1);
    }
    progress.reset();

    if (counter > 0) {
        QMessageBox::information(0, tr("KeePassXC: Removed permissions"),
                                 tr("Successfully removed permissions from %n entry(s).", "", counter),
                                 QMessageBox::Ok);
    } else {
        QMessageBox::information(0, tr("KeePassXC: No entry with permissions found!"),
                                 tr("The active database does not contain an entry with permissions."),
                                 QMessageBox::Ok);
    }
}

QList<Entry*> BrowserService::sortEntries(QList<Entry*>& pwEntries, const QString& host, const QString& entryUrl)
{
    QUrl url(entryUrl);
    if (url.scheme().isEmpty()) {
        url.setScheme("http");
    }

    const QString submitUrl = url.toString(QUrl::StripTrailingSlash);
    const QString baseSubmitUrl = url.toString(QUrl::StripTrailingSlash | QUrl::RemovePath | QUrl::RemoveQuery | QUrl::RemoveFragment);

    QMultiMap<int, const Entry*> priorities;
    for (const Entry* entry : pwEntries) {
        priorities.insert(sortPriority(entry, host, submitUrl, baseSubmitUrl), entry);
    }

    QString field = BrowserSettings::sortByTitle() ? "Title" : "UserName";
    std::sort(pwEntries.begin(), pwEntries.end(), [&priorities, &field](const Entry* left, const Entry* right) {
        int res = priorities.key(left) - priorities.key(right);
        if (res == 0) {
            return QString::localeAwareCompare(left->attributes()->value(field), right->attributes()->value(field)) < 0;
        }
        return res < 0;
    });

    return pwEntries;
}

bool BrowserService::confirmEntries(QList<Entry*>& pwEntriesToConfirm, const QString& url, const QString& host, const QString& submitHost, const QString& realm)
{
    if (pwEntriesToConfirm.isEmpty() || m_dialogActive) {
        return false;
    }

    m_dialogActive = true;
    BrowserAccessControlDialog accessControlDialog;
    accessControlDialog.setUrl(url);
    accessControlDialog.setItems(pwEntriesToConfirm);

    int res = accessControlDialog.exec();
    if (accessControlDialog.remember()) {
        for (Entry* entry : pwEntriesToConfirm) {
            BrowserEntryConfig config;
            config.load(entry);
            if (res == QDialog::Accepted) {
                config.allow(host);
                if (!submitHost.isEmpty() && host != submitHost)
                    config.allow(submitHost);
            } else if (res == QDialog::Rejected) {
                config.deny(host);
                if (!submitHost.isEmpty() && host != submitHost) {
                    config.deny(submitHost);
                }
            }
            if (!realm.isEmpty()) {
                config.setRealm(realm);
            }
            config.save(entry);
        }
    }

    if (res == QDialog::Accepted) {
        return true;
    }

    m_dialogActive = false;
    return false;
}

QJsonObject BrowserService::prepareEntry(const Entry* entry)
{
    QJsonObject res;
    res["login"] = entry->resolvePlaceholder(entry->username());
    res["password"] = entry->resolvePlaceholder(entry->password());
    res["name"] = entry->resolvePlaceholder(entry->title());
    res["uuid"] = entry->resolvePlaceholder(entry->uuid().toHex());

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

BrowserService::Access BrowserService::checkAccess(const Entry* entry, const QString& host, const QString& submitHost, const QString& realm)
{
    BrowserEntryConfig config;
    if (!config.load(entry)) {
        return Unknown;
    }
    if ((config.isAllowed(host)) && (submitHost.isEmpty() || config.isAllowed(submitHost))) {
        return Allowed;
    }
    if ((config.isDenied(host)) || (!submitHost.isEmpty() && config.isDenied(submitHost))) {
        return Denied;
    }
    if (!realm.isEmpty() && config.realm() != realm) {
        return Denied;
    }
    return Unknown;
}

Group* BrowserService::findCreateAddEntryGroup()
{
    Database* db = getDatabase();
    if (!db) {
        return nullptr;
    }

    Group* rootGroup = db->rootGroup();
    if (!rootGroup) {
        return nullptr;
    }

    const QString groupName = QLatin1String(KEEPASSXCBROWSER_GROUP_NAME); //TODO: setting to decide where new keys are created

    for (const Group* g : rootGroup->groupsRecursive(true)) {
        if (g->name() == groupName) {
            return db->resolveGroup(g->uuid());
        }
    }

    Group* group = new Group();
    group->setUuid(Uuid::random());
    group->setName(groupName);
    group->setIcon(KEEPASSXCBROWSER_DEFAULT_ICON);
    group->setParent(rootGroup);
    return group;
}

int BrowserService::sortPriority(const Entry* entry, const QString& host, const QString& submitUrl, const QString& baseSubmitUrl) const
{
    QUrl url(entry->url());
    if (url.scheme().isEmpty()) {
        url.setScheme("http");
    }
    const QString entryURL = url.toString(QUrl::StripTrailingSlash);
    const QString baseEntryURL = url.toString(QUrl::StripTrailingSlash | QUrl::RemovePath | QUrl::RemoveQuery | QUrl::RemoveFragment);

    if (submitUrl == entryURL) {
        return 100;
    }
    if (submitUrl.startsWith(entryURL) && entryURL != host && baseSubmitUrl != entryURL) {
        return 90;
    }
    if (submitUrl.startsWith(baseEntryURL) && entryURL != host && baseSubmitUrl != baseEntryURL) {
        return 80;
    }
    if (entryURL == host) {
        return 70;
    }
    if (entryURL == baseSubmitUrl) {
        return 60;
    }
    if (entryURL.startsWith(submitUrl)) {
        return 50;
    }
    if (entryURL.startsWith(baseSubmitUrl) && baseSubmitUrl != host) {
        return 40;
    }
    if (submitUrl.startsWith(entryURL)) {
        return 30;
    }
    if (submitUrl.startsWith(baseEntryURL)) {
        return 20;
    }
    if (entryURL.startsWith(host)) {
        return 10;
    }
    if (host.startsWith(entryURL)) {
        return 5;
    }
    return 0;
}

bool BrowserService::matchUrlScheme(const QString& url)
{
    QRegularExpression re("^(http|https|ftp|ftps)://");
    QRegularExpressionMatch match = re.match(url);
    return match.hasMatch();
}

bool BrowserService::removeFirstDomain(QString& hostname)
{
    int pos = hostname.indexOf(".");
    if (pos < 0) {
        return false;
    }

    // Don't remove the second-level domain if it's the only one
    if (hostname.count(".") > 1) {
        hostname = hostname.mid(pos + 1);
        return !hostname.isEmpty();
    }

    // Nothing removed
    return false;
}

Database* BrowserService::getDatabase()
{
    if (DatabaseWidget* dbWidget = m_dbTabWidget->currentDatabaseWidget()) {
        if (Database* db = dbWidget->database()) {
            return db;
        }
    }
    return nullptr;
}

void BrowserService::databaseLocked(DatabaseWidget* dbWidget)
{
    if (dbWidget) {
        emit databaseLocked();
    }
}

void BrowserService::databaseUnlocked(DatabaseWidget* dbWidget)
{
    if (dbWidget) {
        emit databaseUnlocked();
    }
}

void BrowserService::activateDatabaseChanged(DatabaseWidget* dbWidget)
{
    if (dbWidget) {
        auto currentMode = dbWidget->currentMode();
        if (currentMode == DatabaseWidget::ViewMode || currentMode == DatabaseWidget::EditMode) {
            emit databaseUnlocked();
        } else {
            emit databaseLocked();
        }
    }
}
