/*
 *  Copyright (C) 2023 KeePassXC Team <team@keepassxc.org>
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

#include "BrowserPasskeysConfirmationDialog.h"
#include "ui_BrowserPasskeysConfirmationDialog.h"

#include "core/Entry.h"
#include <QCloseEvent>
#include <QUrl>

#define STEP 1000

BrowserPasskeysConfirmationDialog::BrowserPasskeysConfirmationDialog(QWidget* parent)
    : QDialog(parent)
    , m_ui(new Ui::BrowserPasskeysConfirmationDialog())
{
    setWindowFlags(windowFlags() | Qt::WindowStaysOnTopHint);

    m_ui->setupUi(this);

    connect(m_ui->credentialsTable, SIGNAL(cellDoubleClicked(int, int)), this, SLOT(accept()));
    connect(m_ui->authenticateButton, SIGNAL(clicked()), SLOT(accept()));
    connect(m_ui->cancelButton, SIGNAL(clicked()), SLOT(reject()));

    connect(&m_timer, SIGNAL(timeout()), this, SLOT(updateProgressBar()));
    connect(&m_timer, SIGNAL(timeout()), this, SLOT(updateSeconds()));
}

BrowserPasskeysConfirmationDialog::~BrowserPasskeysConfirmationDialog()
{
}

void BrowserPasskeysConfirmationDialog::registerCredential(const QString& username, const QString& siteId, int timeout)
{
    m_ui->confirmationLabel->setText(
        tr("Do you want to register Passkey credentials for:\n%1 (%2)?").arg(username, siteId));
    m_ui->authenticateButton->setText(tr("Register"));
    m_ui->credentialsTable->setVisible(false);

    startCounter(timeout);
}

void BrowserPasskeysConfirmationDialog::authenticateCredential(const QList<Entry*>& entries,
                                                               const QString& origin,
                                                               int timeout)
{
    m_entries = entries;
    m_ui->confirmationLabel->setText(tr("Authenticate Passkey credentials for:%1?").arg(origin));
    m_ui->credentialsTable->setRowCount(entries.count());
    m_ui->credentialsTable->setColumnCount(1);

    int row = 0;
    for (const auto& entry : entries) {
        auto item = new QTableWidgetItem();
        item->setText(entry->title() + " - " + entry->username());
        m_ui->credentialsTable->setItem(row, 0, item);

        if (row == 0) {
            item->setSelected(true);
        }

        ++row;
    }

    m_ui->credentialsTable->resizeColumnsToContents();
    m_ui->credentialsTable->horizontalHeader()->setStretchLastSection(true);

    startCounter(timeout);
}

Entry* BrowserPasskeysConfirmationDialog::getSelectedEntry() const
{
    auto selectedItem = m_ui->credentialsTable->currentItem();
    return m_entries[selectedItem->row()];
}

void BrowserPasskeysConfirmationDialog::updateProgressBar()
{
    if (m_counter < m_ui->progressBar->maximum()) {
        m_ui->progressBar->setValue(m_ui->progressBar->maximum() - m_counter);
        m_ui->progressBar->update();
    } else {
        emit reject();
    }
}

void BrowserPasskeysConfirmationDialog::updateSeconds()
{
    ++m_counter;
    updateTimeoutLabel();
}

void BrowserPasskeysConfirmationDialog::startCounter(int timeout)
{
    m_counter = 0;
    m_ui->progressBar->setMaximum(timeout / STEP);
    updateProgressBar();
    updateTimeoutLabel();
    m_timer.start(STEP);
}

void BrowserPasskeysConfirmationDialog::updateTimeoutLabel()
{
    m_ui->timeoutLabel->setText(tr("Timeout in <b>%n</b> seconds...", "", m_ui->progressBar->maximum() - m_counter));
}
