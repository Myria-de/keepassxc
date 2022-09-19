/*
 *  Copyright (C) 2022 KeePassXC Team <team@keepassxc.org>
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

#ifndef KEEPASSXC_BROWSERWEBAUTHNCONFIRMATIONDIALOG_H
#define KEEPASSXC_BROWSERWEBAUTHNCONFIRMATIONDIALOG_H

#include <QDialog>
#include <QTableWidget>
#include <QTimer>

class Entry;

namespace Ui
{
    class BrowserWebAuthnConfirmationDialog;
}

class BrowserWebAuthnConfirmationDialog : public QDialog
{
    Q_OBJECT

public:
    explicit BrowserWebAuthnConfirmationDialog(QWidget* parent = nullptr);
    ~BrowserWebAuthnConfirmationDialog() override;

    void registerCredential(const QString& username, const QString& siteId, int timeout);
    void authenticateCredential(const QList<Entry*>& entries, const QString& origin, int timeout);
    Entry* getSelectedEntry() const;

private slots:
    void updateProgressBar();
    void updateSeconds();

private:
    void startCounter(int timeout);
    void updateTimeoutLabel();

private:
    QScopedPointer<Ui::BrowserWebAuthnConfirmationDialog> m_ui;
    QList<Entry*> m_entries;
    QTimer m_timer;
    int m_counter;
};

#endif // KEEPASSXC_BROWSERWEBAUTHNCONFIRMATIONDIALOG_H
