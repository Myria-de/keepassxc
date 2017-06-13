/*
*  Copyright (C) 2013 Francois Ferrand
*  Copyright (C) 2017 KeePassXC Team <team@keepassxc.org>
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

#include "BrowserOptionDialog.h"
#include "ui_BrowserOptionDialog.h"
#include "BrowserSettings.h"

#include "core/FilePath.h"

#include <QMessageBox>

BrowserOptionDialog::BrowserOptionDialog(QWidget *parent) :
    QWidget(parent),
    m_ui(new Ui::BrowserOptionDialog())
{
    m_ui->setupUi(this);
    connect(m_ui->removeSharedEncryptionKeys, SIGNAL(clicked()), this, SIGNAL(removeSharedEncryptionKeys()));
    connect(m_ui->removeStoredPermissions, SIGNAL(clicked()), this, SIGNAL(removeStoredPermissions()));

    m_ui->warningWidget->showMessage(tr("The following options can be dangerous!\nChange them only if you know what you are doing."), MessageWidget::Warning);
    m_ui->warningWidget->setIcon(FilePath::instance()->icon("status", "dialog-warning"));
    m_ui->warningWidget->setCloseButtonVisible(false);

    m_ui->tabWidget->setEnabled(m_ui->enableBrowserSupport->isChecked());
    connect(m_ui->enableBrowserSupport, SIGNAL(toggled(bool)), m_ui->tabWidget, SLOT(setEnabled(bool)));
}

BrowserOptionDialog::~BrowserOptionDialog()
{
}

void BrowserOptionDialog::loadSettings()
{
    BrowserSettings settings;
    m_ui->enableBrowserSupport->setChecked(settings.isEnabled());

    m_ui->showNotification->setChecked(settings.showNotification());
    m_ui->bestMatchOnly->setChecked(settings.bestMatchOnly());
    m_ui->unlockDatabase->setChecked(settings.unlockDatabase());
    m_ui->matchUrlScheme->setChecked(settings.matchUrlScheme());
    if (settings.sortByUsername())
        m_ui->sortByUsername->setChecked(true);
    else
        m_ui->sortByTitle->setChecked(true);
    m_ui->udpPort->setText(QString::number(settings.udpPort()));
    m_ui->alwaysAllowAccess->setChecked(settings.alwaysAllowAccess());
    m_ui->alwaysAllowUpdate->setChecked(settings.alwaysAllowUpdate());
    m_ui->searchInAllDatabases->setChecked(settings.searchInAllDatabases());
    m_ui->supportKphFields->setChecked(settings.supportKphFields());

    m_ui->passwordGenerator->loadSettings();
}

void BrowserOptionDialog::saveSettings()
{
    BrowserSettings settings;
    settings.setEnabled(m_ui->enableBrowserSupport->isChecked());
    settings.setShowNotification(m_ui->showNotification->isChecked());
    settings.setBestMatchOnly(m_ui->bestMatchOnly->isChecked());
    settings.setUnlockDatabase(m_ui->unlockDatabase->isChecked());
    settings.setMatchUrlScheme(m_ui->matchUrlScheme->isChecked());
    settings.setSortByUsername(m_ui->sortByUsername->isChecked());

    int port = m_ui->udpPort->text().toInt();
    if (port < 1024) {
        QMessageBox::warning(this, tr("Cannot bind to privileged ports"),
            tr("Cannot bind to privileged ports below 1024!\nUsing default port 19700."));
        port = 19700;
    }
    settings.setUdpPort(port);

    settings.setAlwaysAllowAccess(m_ui->alwaysAllowAccess->isChecked());
    settings.setAlwaysAllowUpdate(m_ui->alwaysAllowUpdate->isChecked());
    settings.setSearchInAllDatabases(m_ui->searchInAllDatabases->isChecked());
    settings.setSupportKphFields(m_ui->supportKphFields->isChecked());

    m_ui->passwordGenerator->saveSettings();
}
