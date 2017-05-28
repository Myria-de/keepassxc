/**
 ***************************************************************************
 * @file BrowserOptionDialog.h
 *
 * @brief
 *
 * Copyright (C) 2013
 *
 * @author	Francois Ferrand
 * @date	4/2013
 ***************************************************************************
 */

#ifndef BROWSEROPTIONDIALOG_H
#define BROWSEROPTIONDIALOG_H

#include <QWidget>
#include <QScopedPointer>

namespace Ui {
class BrowserOptionDialog;
}

class BrowserOptionDialog : public QWidget
{
    Q_OBJECT

public:
    explicit BrowserOptionDialog(QWidget *parent = nullptr);
    ~BrowserOptionDialog();

public slots:
    void loadSettings();
    void saveSettings();

signals:
    void removeSharedEncryptionKeys();
    void removeStoredPermissions();

private:
    QScopedPointer<Ui::BrowserOptionDialog> m_ui;
};

#endif // BROWSEROPTIONDIALOG_H
