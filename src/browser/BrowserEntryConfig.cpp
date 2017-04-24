/**
 ***************************************************************************
 * @file BrowserEntryConfig.cpp
 *
 * @brief
 *
 * Copyright (C) 2013
 *
 * @author	Francois Ferrand
 * @date	4/2013
 ***************************************************************************
 */

#include "BrowserEntryConfig.h"
#include <QtCore>
#include "core/Entry.h"
#include "core/EntryAttributes.h"

static const char KEEPASSBROWSER_NAME[] = "chromeKeePassXC Settings";  //TODO: duplicated string (also in Service.cpp)


BrowserEntryConfig::BrowserEntryConfig(QObject *parent) :
    QObject(parent)
{
}

QStringList BrowserEntryConfig::allowedHosts() const
{
    return m_allowedHosts.toList();
}

void BrowserEntryConfig::setAllowedHosts(const QStringList &allowedHosts)
{
    m_allowedHosts = allowedHosts.toSet();
}

QStringList BrowserEntryConfig::deniedHosts() const
{
    return m_deniedHosts.toList();
}

void BrowserEntryConfig::setDeniedHosts(const QStringList &deniedHosts)
{
    m_deniedHosts = deniedHosts.toSet();
}

bool BrowserEntryConfig::isAllowed(const QString &host)
{
    return m_allowedHosts.contains(host);
}

void BrowserEntryConfig::allow(const QString &host)
{
    m_allowedHosts.insert(host);
    m_deniedHosts.remove(host);
}

bool BrowserEntryConfig::isDenied(const QString &host)
{
    return m_deniedHosts.contains(host);
}

void BrowserEntryConfig::deny(const QString &host)
{
    m_deniedHosts.insert(host);
    m_allowedHosts.remove(host);
}

QString BrowserEntryConfig::realm() const
{
    return m_realm;
}

void BrowserEntryConfig::setRealm(const QString &realm)
{
    m_realm = realm;
}

bool BrowserEntryConfig::load(const Entry *entry)
{
    QString s = entry->attributes()->value(KEEPASSBROWSER_NAME);
    if (s.isEmpty())
        return false;

    QJsonDocument doc = QJsonDocument::fromJson(s.toUtf8());
    if (doc.isNull())
        return false;

    QVariantMap map = doc.object().toVariantMap();
    for (QVariantMap::iterator iter = map.begin(); iter != map.end(); ++iter) {
        setProperty(iter.key().toLatin1(), iter.value());
    }
    return true;
}

void BrowserEntryConfig::save(Entry *entry)
{
    QVariantMap v = qo2qv(this);
    QJsonObject o = QJsonObject::fromVariantMap(v);
    QByteArray json = QJsonDocument(o).toJson(QJsonDocument::Compact);
    entry->attributes()->set(KEEPASSBROWSER_NAME, json);
}
