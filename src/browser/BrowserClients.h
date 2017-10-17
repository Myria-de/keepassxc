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

#ifndef BROWSERCLIENTS_H
#define BROWSERCLIENTS_H

#include <QJsonObject>
#include <QMutex>
#include <QVector>
#include <QSharedPointer>

#include "BrowserAction.h"

class BrowserClients
{
    struct Client {
        QString                         clientID;
        quint16                         clientPort;
        QSharedPointer<BrowserAction>   browserAction;
    };

    typedef QSharedPointer<Client>      ClientPtr;

public:
    BrowserClients(BrowserService& browserService);
    ~BrowserClients();

    const QJsonObject               readResponse(const QByteArray& arr, const quint16 clientPort = 0);
    const QVector<quint16>          getAllActivePorts();

private:
    QJsonObject                     byteArrayToJson(const QByteArray& arr) const;
    QString                         getClientID(const QJsonObject& json) const;
    const ClientPtr                 getClient(const QString& clientID, const quint16 clientPort);

private:
    QMutex                          m_mutex;
    QVector<ClientPtr>              m_clients;
    BrowserService&                 m_browserService;
};

#endif // BROWSERCLIENTS_H
