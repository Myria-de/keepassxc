/**
 ***************************************************************************
 * @file BrowserAccessControlDialog.cpp
 *
 * @brief
 *
 * Copyright (C) 2013
 *
 * @author	Francois Ferrand
 * @date	4/2013
 ***************************************************************************
 */

#include "BrowserAccessControlDialog.h"
#include "ui_BrowserAccessControlDialog.h"
#include "core/Entry.h"

BrowserAccessControlDialog::BrowserAccessControlDialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::BrowserAccessControlDialog())
{
    this->setWindowFlags(windowFlags() | Qt::WindowStaysOnTopHint);

    ui->setupUi(this);
    connect(ui->allowButton, SIGNAL(clicked()), this, SLOT(accept()));
    connect(ui->denyButton, SIGNAL(clicked()), this, SLOT(reject()));
}

BrowserAccessControlDialog::~BrowserAccessControlDialog()
{
}

void BrowserAccessControlDialog::setUrl(const QString &url)
{
    ui->label->setText(QString(tr("%1 has requested access to passwords for the following item(s).\n"
                                  "Please select whether you want to allow access.")).arg(QUrl(url).host()));
}

void BrowserAccessControlDialog::setItems(const QList<Entry *> &items)
{
    Q_FOREACH (Entry * entry, items)
        ui->itemsList->addItem(entry->title() + " - " + entry->username());
}

bool BrowserAccessControlDialog::remember() const
{
    return ui->rememberDecisionCheckBox->isChecked();
}

void BrowserAccessControlDialog::setRemember(bool r)
{
    ui->rememberDecisionCheckBox->setChecked(r);
}
