#ifndef BROWSERSERVICE_H
#define BROWSERSERVICE_H

#include <QObject>
#include "gui/DatabaseTabWidget.h"

class BrowserService : public QObject
{
    Q_OBJECT

public:
    explicit    BrowserService(DatabaseTabWidget* parent);


    bool        isDatabaseOpened() const;
    bool        openDatabase();
    QString     getDatabaseRootUuid();
    QString     getDatabaseRecycleBinUuid();
    Entry*      getConfigEntry(bool create = false);
    QString     storeKey(const QString &key);
    QString     getKey(const QString &id);

private:
    DatabaseTabWidget * const m_dbTabWidget;
};

#endif // BROWSERSERVICE_H