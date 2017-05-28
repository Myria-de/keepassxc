/**
 ***************************************************************************
 * @file BrowserOptionDialog.cpp
 *
 * @brief
 *
 * Copyright (C) 2013
 *
 * @author	    Francois Ferrand
 * @date	    4/2013
 *
 * @modified    Sami Vänttinen
 * @date        4/2017
 ***************************************************************************
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
    settings.setAlwaysAllowAccess(m_ui->alwaysAllowAccess->isChecked());
    settings.setAlwaysAllowUpdate(m_ui->alwaysAllowUpdate->isChecked());
    settings.setSearchInAllDatabases(m_ui->searchInAllDatabases->isChecked());
    settings.setSupportKphFields(m_ui->supportKphFields->isChecked());

    m_ui->passwordGenerator->saveSettings();
}
