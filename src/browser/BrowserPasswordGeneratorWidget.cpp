/*
 *  Copyright (C) 2013 Felix Geyer <debfx@fobos.de>
 *  Copyright (C) 2017 KeePassXC Team <team@keepassxc.org>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 2 or (at your option)
 *  version 3 of the License.
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
#include <QDir>

#include "core/Config.h"
#include "core/PasswordGenerator.h"
#include "core/FilePath.h"
#include "gui/Clipboard.h"

BrowserPasswordGeneratorWidget::BrowserPasswordGeneratorWidget(QWidget* parent)
    : QWidget(parent)
    , m_updatingSpinBox(false)
    , m_passwordGenerator(new PasswordGenerator())
    , m_dicewareGenerator(new PassphraseGenerator())
    , m_ui(new Ui::BrowserPasswordGeneratorWidget())
{
    m_ui->setupUi(this);

    connect(m_ui->sliderLength, SIGNAL(valueChanged(int)), SLOT(passwordSliderMoved()));
    connect(m_ui->spinBoxLength, SIGNAL(valueChanged(int)), SLOT(passwordSpinBoxChanged()));

    connect(m_ui->sliderWordCount, SIGNAL(valueChanged(int)), SLOT(dicewareSliderMoved()));
    connect(m_ui->spinBoxWordCount, SIGNAL(valueChanged(int)), SLOT(dicewareSpinBoxChanged()));

    connect(m_ui->editWordSeparator, SIGNAL(textChanged(QString)), SLOT(updateGenerator()));
    connect(m_ui->comboBoxWordList, SIGNAL(currentIndexChanged(int)), SLOT(updateGenerator()));
    connect(m_ui->optionButtons, SIGNAL(buttonClicked(int)), SLOT(updateGenerator()));
    connect(m_ui->tabWidget, SIGNAL(currentChanged(int)), SLOT(updateGenerator()));

    // set font size of password quality and entropy labels dynamically to 80% of
    // the default font size, but make it no smaller than 8pt
    QFont defaultFont;
    int smallerSize = static_cast<int>(defaultFont.pointSize() * 0.8f);
    if (smallerSize >= 8) {
        defaultFont.setPointSize(smallerSize);
        m_ui->entropyLabel->setFont(defaultFont);
        m_ui->strengthLabel->setFont(defaultFont);
    }

    // set default separator to Space
    m_ui->editWordSeparator->setText(" ");

    QDir path(filePath()->dataPath("wordlists/"));
    QStringList files = path.entryList(QDir::Files);
    m_ui->comboBoxWordList->addItems(files);
    if (files.size() > 1) {
        m_ui->comboBoxWordList->setVisible(true);
        m_ui->labelWordList->setVisible(true);
    } else {
        m_ui->comboBoxWordList->setVisible(false);
        m_ui->labelWordList->setVisible(false);
    }

    loadSettings();
    reset();
}

BrowserPasswordGeneratorWidget::~BrowserPasswordGeneratorWidget()
{
}

void BrowserPasswordGeneratorWidget::loadSettings()
{
    // Password config
    m_ui->checkBoxLower->setChecked(config()->get("Browser/generator/LowerCase", true).toBool());
    m_ui->checkBoxUpper->setChecked(config()->get("Browser/generator/UpperCase", true).toBool());
    m_ui->checkBoxNumbers->setChecked(config()->get("Browser/generator/Numbers", true).toBool());
    m_ui->checkBoxSpecialChars->setChecked(config()->get("Browser/generator/SpecialChars", false).toBool());
    m_ui->checkBoxExtASCII->setChecked(config()->get("Browser/generator/EASCII", false).toBool());
    m_ui->checkBoxExcludeAlike->setChecked(config()->get("Browser/generator/ExcludeAlike", true).toBool());
    m_ui->checkBoxEnsureEvery->setChecked(config()->get("Browser/generator/EnsureEvery", true).toBool());
    m_ui->spinBoxLength->setValue(config()->get("Browser/generator/Length", 16).toInt());

    // Diceware config
    m_ui->spinBoxWordCount->setValue(config()->get("Browser/generator/WordCount", 6).toInt());
    m_ui->editWordSeparator->setText(config()->get("Browser/generator/WordSeparator", " ").toString());
    m_ui->comboBoxWordList->setCurrentText(config()->get("Browser/generator/WordList", "eff_large.wordlist").toString());

    // Password or diceware?
    m_ui->tabWidget->setCurrentIndex(config()->get("Browser/generator/Type", 0).toInt());
}

void BrowserPasswordGeneratorWidget::saveSettings()
{
    // Password config
    config()->set("Browser/generator/LowerCase", m_ui->checkBoxLower->isChecked());
    config()->set("Browser/generator/UpperCase", m_ui->checkBoxUpper->isChecked());
    config()->set("Browser/generator/Numbers", m_ui->checkBoxNumbers->isChecked());
    config()->set("Browser/generator/SpecialChars", m_ui->checkBoxSpecialChars->isChecked());
    config()->set("Browser/generator/EASCII", m_ui->checkBoxExtASCII->isChecked());
    config()->set("Browser/generator/ExcludeAlike", m_ui->checkBoxExcludeAlike->isChecked());
    config()->set("Browser/generator/EnsureEvery", m_ui->checkBoxEnsureEvery->isChecked());
    config()->set("Browser/generator/Length", m_ui->spinBoxLength->value());

    // Diceware config
    config()->set("Browser/generator/WordCount", m_ui->spinBoxWordCount->value());
    config()->set("Browser/generator/WordSeparator", m_ui->editWordSeparator->text());
    config()->set("Browser/generator/WordList", m_ui->comboBoxWordList->currentText());

    // Password or diceware?
    config()->set("Browser/generator/Type", m_ui->tabWidget->currentIndex());
}

void BrowserPasswordGeneratorWidget::reset()
{
    setStandaloneMode(false);
    updateGenerator();
}

void BrowserPasswordGeneratorWidget::setStandaloneMode(bool standalone)
{
    m_standalone = standalone;
}

void BrowserPasswordGeneratorWidget::regeneratePassword()
{
    if (m_ui->tabWidget->currentIndex() == Password) {
        if (m_passwordGenerator->isValid()) {
            QString password = m_passwordGenerator->generatePassword();
            updatePasswordStrength(password);
        }
    } else {
        if (m_dicewareGenerator->isValid()) {
            QString password = m_dicewareGenerator->generatePassphrase();
            updatePasswordStrength(password);
        }
    }
}

void BrowserPasswordGeneratorWidget::updatePasswordStrength(const QString& password)
{
    double entropy = 0.0;
    if (m_ui->tabWidget->currentIndex() == Password) {
        entropy = m_passwordGenerator->calculateEntropy(password);
    } else {
        entropy = m_dicewareGenerator->calculateEntropy(password);
    }

    m_ui->entropyLabel->setText(tr("Entropy: %1 bit").arg(QString::number(entropy, 'f', 2)));

    if (entropy > m_ui->entropyProgressBar->maximum()) {
        entropy = m_ui->entropyProgressBar->maximum();
    }
    m_ui->entropyProgressBar->setValue(entropy);

    colorStrengthIndicator(entropy);
}

void BrowserPasswordGeneratorWidget::applyPassword()
{
    saveSettings();
    emit dialogTerminated();
}

void BrowserPasswordGeneratorWidget::passwordSliderMoved()
{
    if (m_updatingSpinBox) {
        return;
    }

    m_ui->spinBoxLength->setValue(m_ui->sliderLength->value());

    updateGenerator();
}

void BrowserPasswordGeneratorWidget::passwordSpinBoxChanged()
{
    if (m_updatingSpinBox) {
        return;
    }

    // Interlock so that we don't update twice - this causes issues as the spinbox can go higher than slider
    m_updatingSpinBox = true;

    m_ui->sliderLength->setValue(m_ui->spinBoxLength->value());

    m_updatingSpinBox = false;

    updateGenerator();
}

void BrowserPasswordGeneratorWidget::dicewareSliderMoved()
{
    m_ui->spinBoxWordCount->setValue(m_ui->sliderWordCount->value());

    updateGenerator();
}

void BrowserPasswordGeneratorWidget::dicewareSpinBoxChanged()
{
    m_ui->sliderWordCount->setValue(m_ui->spinBoxWordCount->value());

    updateGenerator();
}

void BrowserPasswordGeneratorWidget::colorStrengthIndicator(double entropy)
{
    // Take the existing stylesheet and convert the text and background color to arguments
    QString style = m_ui->entropyProgressBar->styleSheet();
    QRegularExpression re("(QProgressBar::chunk\\s*\\{.*?background-color:)[^;]+;",
                          QRegularExpression::CaseInsensitiveOption |
                          QRegularExpression::DotMatchesEverythingOption);
    style.replace(re, "\\1 %1;");

    // Set the color and background based on entropy
    // colors are taking from the KDE breeze palette
    // <https://community.kde.org/KDE_Visual_Design_Group/HIG/Color>
    if (entropy < 40) {
        m_ui->entropyProgressBar->setStyleSheet(style.arg("#c0392b"));
        m_ui->strengthLabel->setText(tr("Password Quality: %1").arg(tr("Poor")));
    } else if (entropy >= 40 && entropy < 65) {
        m_ui->entropyProgressBar->setStyleSheet(style.arg("#f39c1f"));
        m_ui->strengthLabel->setText(tr("Password Quality: %1").arg(tr("Weak")));
    } else if (entropy >= 65 && entropy < 100) {
        m_ui->entropyProgressBar->setStyleSheet(style.arg("#11d116"));
        m_ui->strengthLabel->setText(tr("Password Quality: %1").arg(tr("Good")));
    } else {
        m_ui->entropyProgressBar->setStyleSheet(style.arg("#27ae60"));
        m_ui->strengthLabel->setText(tr("Password Quality: %1").arg(tr("Excellent")));
    }
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

    if (m_ui->checkBoxExtASCII->isChecked()) {
        classes |= PasswordGenerator::EASCII;
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
    if (m_ui->tabWidget->currentIndex() == Password) {
        PasswordGenerator::CharClasses classes = charClasses();
        PasswordGenerator::GeneratorFlags flags = generatorFlags();

        int minLength = 0;
        if (flags.testFlag(PasswordGenerator::CharFromEveryGroup)) {
            if (classes.testFlag(PasswordGenerator::LowerLetters)) {
                minLength++;
            }
            if (classes.testFlag(PasswordGenerator::UpperLetters)) {
                minLength++;
            }
            if (classes.testFlag(PasswordGenerator::Numbers)) {
                minLength++;
            }
            if (classes.testFlag(PasswordGenerator::SpecialCharacters)) {
                minLength++;
            }
            if (classes.testFlag(PasswordGenerator::EASCII)) {
                minLength++;
            }
        }
        minLength = qMax(minLength, 1);

        if (m_ui->spinBoxLength->value() < minLength) {
            m_updatingSpinBox = true;
            m_ui->spinBoxLength->setValue(minLength);
            m_ui->sliderLength->setValue(minLength);
            m_updatingSpinBox = false;
        }

        m_ui->spinBoxLength->setMinimum(minLength);
        m_ui->sliderLength->setMinimum(minLength);

        m_passwordGenerator->setLength(m_ui->spinBoxLength->value());
        m_passwordGenerator->setCharClasses(classes);
        m_passwordGenerator->setFlags(flags);
    } else {
        int minWordCount = 1;

        if (m_ui->spinBoxWordCount->value() < minWordCount) {
            m_updatingSpinBox = true;
            m_ui->spinBoxWordCount->setValue(minWordCount);
            m_ui->sliderWordCount->setValue(minWordCount);
            m_updatingSpinBox = false;
        }

        m_ui->spinBoxWordCount->setMinimum(minWordCount);
        m_ui->sliderWordCount->setMinimum(minWordCount);

        m_dicewareGenerator->setWordCount(m_ui->spinBoxWordCount->value());
        if (!m_ui->comboBoxWordList->currentText().isEmpty()) {
            QString path = filePath()->dataPath("wordlists/" + m_ui->comboBoxWordList->currentText());
            m_dicewareGenerator->setWordList(path);
        }
        m_dicewareGenerator->setWordSeparator(m_ui->editWordSeparator->text());
    }

    regeneratePassword();
}
