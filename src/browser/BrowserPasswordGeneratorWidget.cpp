/*
*  Copyright (C) 2013 Francois Ferrand
*  Copyright (C) 2017 KeePassXC Team <team@keepassxc.org>
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

#include "BrowserPasswordGeneratorWidget.h"
#include "ui_BrowserPasswordGeneratorWidget.h"

#include <QLineEdit>

#include "core/Config.h"
#include "core/PasswordGenerator.h"
#include "core/FilePath.h"

BrowserPasswordGeneratorWidget::BrowserPasswordGeneratorWidget(QWidget* parent)
    : QWidget(parent)
    , m_updatingSpinBox(false)
    , m_generator(new PasswordGenerator())
    , m_ui(new Ui::BrowserPasswordGeneratorWidget())
{
    m_ui->setupUi(this);

    connect(m_ui->sliderLength, SIGNAL(valueChanged(int)), SLOT(sliderMoved()));
    connect(m_ui->spinBoxLength, SIGNAL(valueChanged(int)), SLOT(spinBoxChanged()));

    connect(m_ui->optionButtons, SIGNAL(buttonClicked(int)), SLOT(updateGenerator()));

    loadSettings();
    reset();
}

BrowserPasswordGeneratorWidget::~BrowserPasswordGeneratorWidget()
{
}

void BrowserPasswordGeneratorWidget::loadSettings()
{
    m_ui->checkBoxLower->setChecked(config()->get("Browser/generator/LowerCase", true).toBool());
    m_ui->checkBoxUpper->setChecked(config()->get("Browser/generator/UpperCase", true).toBool());
    m_ui->checkBoxNumbers->setChecked(config()->get("Browser/generator/Numbers", true).toBool());
    m_ui->checkBoxSpecialChars->setChecked(config()->get("Browser/generator/SpecialChars", false).toBool());

    m_ui->checkBoxExcludeAlike->setChecked(config()->get("Browser/generator/ExcludeAlike", true).toBool());
    m_ui->checkBoxEnsureEvery->setChecked(config()->get("Browser/generator/EnsureEvery", true).toBool());

    m_ui->spinBoxLength->setValue(config()->get("Browser/generator/Length", 16).toInt());
}

void BrowserPasswordGeneratorWidget::saveSettings()
{
    config()->set("Browser/generator/LowerCase", m_ui->checkBoxLower->isChecked());
    config()->set("Browser/generator/UpperCase", m_ui->checkBoxUpper->isChecked());
    config()->set("Browser/generator/Numbers", m_ui->checkBoxNumbers->isChecked());
    config()->set("Browser/generator/SpecialChars", m_ui->checkBoxSpecialChars->isChecked());

    config()->set("Browser/generator/ExcludeAlike", m_ui->checkBoxExcludeAlike->isChecked());
    config()->set("Browser/generator/EnsureEvery", m_ui->checkBoxEnsureEvery->isChecked());

    config()->set("Browser/generator/Length", m_ui->spinBoxLength->value());
}

void BrowserPasswordGeneratorWidget::reset()
{
    updateGenerator();
}

void BrowserPasswordGeneratorWidget::sliderMoved()
{
    if (m_updatingSpinBox) {
        return;
    }

    m_ui->spinBoxLength->setValue(m_ui->sliderLength->value());

    updateGenerator();
}

void BrowserPasswordGeneratorWidget::spinBoxChanged()
{
    // Interlock so that we don't update twice - this causes issues as the spinbox can go higher than slider
    m_updatingSpinBox = true;

    m_ui->sliderLength->setValue(m_ui->spinBoxLength->value());

    m_updatingSpinBox = false;

    updateGenerator();
}

PasswordGenerator::CharClasses BrowserPasswordGeneratorWidget::charClasses()
{
    PasswordGenerator::CharClasses classes;

    if (m_ui->checkBoxLower->isChecked()) {
        classes |= PasswordGenerator::LowerLetters;
    }

    if (m_ui->checkBoxUpper->isChecked()) {
        classes |= PasswordGenerator::UpperLetters;
    }

    if (m_ui->checkBoxNumbers->isChecked()) {
        classes |= PasswordGenerator::Numbers;
    }

    if (m_ui->checkBoxSpecialChars->isChecked()) {
        classes |= PasswordGenerator::SpecialCharacters;
    }

    return classes;
}

PasswordGenerator::GeneratorFlags BrowserPasswordGeneratorWidget::generatorFlags()
{
    PasswordGenerator::GeneratorFlags flags;

    if (m_ui->checkBoxExcludeAlike->isChecked()) {
        flags |= PasswordGenerator::ExcludeLookAlike;
    }

    if (m_ui->checkBoxEnsureEvery->isChecked()) {
        flags |= PasswordGenerator::CharFromEveryGroup;
    }

    return flags;
}

void BrowserPasswordGeneratorWidget::updateGenerator()
{
    m_generator->setLength(m_ui->spinBoxLength->value());
    m_generator->setCharClasses(charClasses());
    m_generator->setFlags(generatorFlags());
}
