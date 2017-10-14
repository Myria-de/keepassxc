/*
*  Copyright (C) 2017 Sami Vänttinen <sami.vanttinen@protonmail.com>
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

#include <QJsonValue>
#include <QJsonParseError>
#include "BrowserClients.h"

BrowserClients::BrowserClients(DatabaseTabWidget* parent) :
    m_mutex(QMutex::Recursive),
    m_dbTabWidget(parent)
{
    m_clients.reserve(1000);
    m_browserAction.reset(new BrowserAction(parent));
}

BrowserClients::~BrowserClients()
{
    m_clients.clear();
}

const QJsonObject BrowserClients::readResponse(const QByteArray& arr, const quint16 clientPort, const bool isProxy)
{
    QJsonObject json;
    const QJsonObject message = byteArrayToJson(arr);
    const QString clientID = getClientID(message);

    if (!clientID.isEmpty()) {
        const BrowserClients::Client& client = getClient(clientID, clientPort, isProxy);
        if (isProxy) {
            if (client.browserAction) {
                json = client.browserAction->readResponse(message);
            }
        } else {
            QMutexLocker locker(&m_mutex);
            if (m_browserAction) {
                json = m_browserAction->readResponse(message);
            }
        }
    }

    return json;
}


// Private functions
// ========================

QJsonObject BrowserClients::byteArrayToJson(const QByteArray& arr) const
{
    QJsonObject json;
    QJsonParseError err;
    QJsonDocument doc(QJsonDocument::fromJson(arr, &err));
    if (doc.isObject()) {
        json = doc.object();
    }

    return json;
}

QString BrowserClients::getClientID(const QJsonObject& json) const
{
    return json["clientID"].toString();
}

const BrowserClients::Client BrowserClients::getClient(const QString& clientID, const quint16 clientPort, const bool isProxy)
{
    QMutexLocker locker(&m_mutex);
    for (const auto &i : m_clients) {
        if (i.clientID.compare(clientID, Qt::CaseSensitive) == 0) {
            return i;
        }
    }

    // clientID not found, create a new client
    m_clients.push_back({ clientID, clientPort, (isProxy ? QSharedPointer<BrowserAction>(new BrowserAction(m_dbTabWidget)) : nullptr) });
    return m_clients.back();
}
