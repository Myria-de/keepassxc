#ifndef BROWSERSERVICE_H
#define BROWSERSERVICE_H

#include <QtCore>
#include <QObject>
//#include "Variant.h"
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
    QString         storeKey(const QString &key);
    QString         getKey(const QString &id);
    QJsonArray      findMatchingEntries(const QString& /*id*/, const QString& url, const QString& submitUrl, const QString& realm);

    QList<Entry*>   searchEntries(Database* db, const QString& hostname);
    QList<Entry*>   searchEntries(const QString& text);

private:
    enum Access     { Denied, Unknown, Allowed};
    //class           SortEntries;

private:
    QJsonObject     prepareEntry(const Entry* entry);
    Access          checkAccess(const Entry* entry, const QString&  host, const QString&  submitHost, const QString&  realm);
    
    int             sortPriority(const Entry *entry, const QString &host, const QString &submitUrl, const QString &baseSubmitUrl) const;
    bool            matchUrlScheme(const QString& url);
    bool            removeFirstDomain(QString& hostname);

private:
    DatabaseTabWidget* const m_dbTabWidget;
};

#endif // BROWSERSERVICE_H