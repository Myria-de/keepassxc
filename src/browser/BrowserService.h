/*
*  Copyright (C) 2013 Francois Ferrand
*  Copyright (C) 2017 KeePassXC Team <team@keepassxc.org>
*  Copyright (C) 2017 Sami Vänttinen <sami.vanttinen@protonmail.com>
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

#ifndef BROWSERSERVICE_H
#define BROWSERSERVICE_H

#include <QtCore>
#include <QObject>
#include "gui/DatabaseTabWidget.h"
#include "core/Entry.h"

class BrowserService : public QObject
{
    Q_OBJECT

    class SortEntries
    {
    public:
        SortEntries(const QHash<const Entry*, int>& priorities, const QString & field):
            m_priorities(priorities), m_field(field)
        {}

        bool operator()(const Entry* left, const Entry* right) const
        {
            int res = m_priorities.value(left) - m_priorities.value(right);
            if (res == 0)
                return QString::localeAwareCompare(left->attributes()->value(m_field), right->attributes()->value(m_field)) < 0;
            return res < 0;
        }

    private:
        const QHash<const Entry*, int>& m_priorities;
        const QString m_field;
    };

public:
    explicit        BrowserService(DatabaseTabWidget* parent);

    bool            isDatabaseOpened() const;
    bool            openDatabase();
    QString         getDatabaseRootUuid();
    QString         getDatabaseRecycleBinUuid();
    Entry*          getConfigEntry(bool create = false);
    QString         getKey(const QString &id);
    void            addEntry(const QString& id, const QString& login, const QString& password, const QString& url, const QString& submitUrl, const QString& realm);
    QList<Entry*>   searchEntries(Database* db, const QString& hostname);
    QList<Entry*>   searchEntries(const QString& text);
    void            removeSharedEncryptionKeys();
    void            removeStoredPermissions();

public slots:
    QJsonArray      findMatchingEntries(const QString& id, const QString& url, const QString& submitUrl, const QString& realm);
    QString         storeKey(const QString &key);
    void            updateEntry(const QString& id, const QString& uuid, const QString& login, const QString& password, const QString& url);

private:
    enum Access     { Denied, Unknown, Allowed};

private:
    QJsonObject     prepareEntry(const Entry* entry);
    Access          checkAccess(const Entry* entry, const QString&  host, const QString&  submitHost, const QString&  realm);
    Group*          findCreateAddEntryGroup();
    int             sortPriority(const Entry *entry, const QString &host, const QString &submitUrl, const QString &baseSubmitUrl) const;
    bool            matchUrlScheme(const QString& url);
    bool            removeFirstDomain(QString& hostname);

private:
    DatabaseTabWidget* const m_dbTabWidget;
};

#endif // BROWSERSERVICE_H
