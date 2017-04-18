/**
 ***************************************************************************
 * @file BrowserAccessControlDialog.h
 *
 * @brief
 *
 * Copyright (C) 2013
 *
 * @author	Francois Ferrand
 * @date	4/2013
 ***************************************************************************
 */

#ifndef BROWSERACCESSCONTROLDIALOG_H
#define BROWSERACCESSCONTROLDIALOG_H

#include <QDialog>
#include <QScopedPointer>

class Entry;

namespace Ui {
class BrowserAccessControlDialog;
}

class BrowserAccessControlDialog : public QDialog
{
    Q_OBJECT
    
public:
    explicit BrowserAccessControlDialog(QWidget *parent = nullptr);
    ~BrowserAccessControlDialog();

    void setUrl(const QString & url);
    void setItems(const QList<Entry *> & items);
    bool remember() const;
    void setRemember(bool r);
    
private:
    QScopedPointer<Ui::BrowserAccessControlDialog> ui;
};

#endif // BROWSERACCESSCONTROLDIALOG_H
