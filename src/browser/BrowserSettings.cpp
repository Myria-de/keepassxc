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

#include "BrowserSettings.h"
#include "core/Config.h"

PasswordGenerator BrowserSettings::m_passwordGenerator;
PassphraseGenerator BrowserSettings::m_passPhraseGenerator;

bool BrowserSettings::isEnabled()
{
    return config()->get("Browser/Enabled", false).toBool();
}

void BrowserSettings::setEnabled(bool enabled)
{
    config()->set("Browser/Enabled", enabled);
}

bool BrowserSettings::showNotification()
{
    return config()->get("Browser/ShowNotification", true).toBool();
}

void BrowserSettings::setShowNotification(bool showNotification)
{
    config()->set("Browser/ShowNotification", showNotification);
}

bool BrowserSettings::bestMatchOnly()
{
    return config()->get("Browser/BestMatchOnly", false).toBool();
}

void BrowserSettings::setBestMatchOnly(bool bestMatchOnly)
{
    config()->set("Browser/BestMatchOnly", bestMatchOnly);
}

bool BrowserSettings::unlockDatabase()
{
    return config()->get("Browser/UnlockDatabase", true).toBool();
}

void BrowserSettings::setUnlockDatabase(bool unlockDatabase)
{
    config()->set("Browser/UnlockDatabase", unlockDatabase);
}

bool BrowserSettings::matchUrlScheme()
{
    return config()->get("Browser/MatchUrlScheme", true).toBool();
}

void BrowserSettings::setMatchUrlScheme(bool matchUrlScheme)
{
    config()->set("Browser/MatchUrlScheme", matchUrlScheme);
}

bool BrowserSettings::sortByUsername()
{
    return config()->get("Browser/SortByUsername", false).toBool();
}

void BrowserSettings::setSortByUsername(bool sortByUsername)
{
    config()->set("Browser/SortByUsername", sortByUsername);
}

bool BrowserSettings::sortByTitle()
{
    return !sortByUsername();
}

void BrowserSettings::setSortByTitle(bool sortByUsertitle)
{
    setSortByUsername(!sortByUsertitle);
}

bool BrowserSettings::alwaysAllowAccess()
{
    return config()->get("Browser/AlwaysAllowAccess", false).toBool();
}

void BrowserSettings::setAlwaysAllowAccess(bool alwaysAllowAccess)
{
    config()->set("Browser/AlwaysAllowAccess", alwaysAllowAccess);
}

bool BrowserSettings::alwaysAllowUpdate()
{
    return config()->get("Browser/AlwaysAllowUpdate", false).toBool();
}

void BrowserSettings::setAlwaysAllowUpdate(bool alwaysAllowUpdate)
{
    config()->set("Browser/AlwaysAllowUpdate", alwaysAllowUpdate);
}

bool BrowserSettings::searchInAllDatabases()
{
    return config()->get("Browser/SearchInAllDatabases", false).toBool();
}

void BrowserSettings::setSearchInAllDatabases(bool searchInAllDatabases)
{
    config()->set("Browser/SearchInAllDatabases", searchInAllDatabases);
}

bool BrowserSettings::supportKphFields()
{
    return config()->get("Browser/SupportKphFields", true).toBool();
}

void BrowserSettings::setSupportKphFields(bool supportKphFields)
{
    config()->set("Browser/SupportKphFields", supportKphFields);
}

int BrowserSettings::udpPort()
{
    static const int PORT = 19700;
    return config()->get("UDP/Port", PORT).toInt();
}

void BrowserSettings::setUdpPort(int port)
{
    config()->set("UDP/Port", port);
}

bool BrowserSettings::supportBrowserProxy()
{
    return config()->get("Browser/SupportBrowserProxy", false).toBool();
}

void BrowserSettings::setSupportBrowserProxy(bool enabled)
{
    config()->set("Browser/SupportBrowserProxy", enabled);
}

bool BrowserSettings::passwordUseNumbers()
{
    return config()->get("Browser/generator/Numbers", true).toBool();
}

void BrowserSettings::setPasswordUseNumbers(bool useNumbers)
{
    config()->set("Browser/generator/Numbers", useNumbers);
}

bool BrowserSettings::passwordUseLowercase()
{
    return config()->get("Browser/generator/LowerCase", true).toBool();
}

void BrowserSettings::setPasswordUseLowercase(bool useLowercase)
{
    config()->set("Browser/generator/LowerCase", useLowercase);
}

bool BrowserSettings::passwordUseUppercase()
{
    return config()->get("Browser/generator/UpperCase", true).toBool();
}

void BrowserSettings::setPasswordUseUppercase(bool useUppercase)
{
    config()->set("Browser/generator/UpperCase", useUppercase);
}

bool BrowserSettings::passwordUseSpecial()
{
    return config()->get("Browser/generator/SpecialChars", false).toBool();
}

void BrowserSettings::setPasswordUseSpecial(bool useSpecial)
{
    config()->set("Browser/generator/SpecialChars", useSpecial);
}

bool BrowserSettings::passwordUseEASCII()
{
    return config()->get("Browser/generator/EASCII", false).toBool();
}

void BrowserSettings::setPasswordUseEASCII(bool useEASCII)
{
    config()->set("Browser/generator/EASCII", useEASCII);
}

int BrowserSettings::passPhraseWordCount()
{
    return config()->get("Browser/generator/WordCount", 6).toInt();
}

void BrowserSettings::setPassPhraseWordCount(int wordCount)
{
    config()->set("Browser/generator/WordCount", wordCount);
}

QString BrowserSettings::passPhraseWordSeparator()
{
    return config()->get("Browser/generator/WordSeparator", " ").toString();
}

void BrowserSettings::setPassPhraseWordSeparator(QString separator)
{
    config()->set("Browser/generator/WordSeparator", separator);
}

int BrowserSettings::generatorType()
{
    return config()->get("Browser/generator/Type", 0).toInt();
}

void BrowserSettings::setGeneratorType(int type)
{
    config()->set("Browser/generator/Type", type);
}

bool BrowserSettings::passwordEveryGroup()
{
    return config()->get("Browser/generator/EnsureEvery", true).toBool();
}

void BrowserSettings::setPasswordEveryGroup(bool everyGroup)
{
    config()->get("Browser/generator/EnsureEvery", everyGroup);
}

bool BrowserSettings::passwordExcludeAlike()
{
    return config()->get("Browser/generator/ExcludeAlike", true).toBool();
}

void BrowserSettings::setPasswordExcludeAlike(bool excludeAlike)
{
    config()->set("Browser/generator/ExcludeAlike", excludeAlike);
}

int BrowserSettings::passwordLength()
{
    return config()->get("Browser/generator/Length", 20).toInt();
}

void BrowserSettings::setPasswordLength(int length)
{
    config()->set("Browser/generator/Length", length);
    m_passwordGenerator.setLength(length);
}

PasswordGenerator::CharClasses BrowserSettings::passwordCharClasses()
{
    PasswordGenerator::CharClasses classes;
    if (passwordUseLowercase())
        classes |= PasswordGenerator::LowerLetters;
    if (passwordUseUppercase())
        classes |= PasswordGenerator::UpperLetters;
    if (passwordUseNumbers())
        classes |= PasswordGenerator::Numbers;
    if (passwordUseSpecial())
        classes |= PasswordGenerator::SpecialCharacters;
    if (passwordUseEASCII())
        classes |= PasswordGenerator::EASCII;
    return classes;
}

PasswordGenerator::GeneratorFlags BrowserSettings::passwordGeneratorFlags()
{
    PasswordGenerator::GeneratorFlags flags;
    if (passwordExcludeAlike())
        flags |= PasswordGenerator::ExcludeLookAlike;
    if (passwordEveryGroup())
        flags |= PasswordGenerator::CharFromEveryGroup;
    return flags;
}

QString BrowserSettings::generatePassword()
{
    if (generatorType() == 0) {
        m_passwordGenerator.setLength(passwordLength());
        m_passwordGenerator.setCharClasses(passwordCharClasses());
        m_passwordGenerator.setFlags(passwordGeneratorFlags());
        return m_passwordGenerator.generatePassword();
    }
    else {
        m_passPhraseGenerator.setWordCount(passPhraseWordCount());
        m_passPhraseGenerator.setWordSeparator(passPhraseWordSeparator());
        return m_passPhraseGenerator.generatePassphrase();
    }
}

int BrowserSettings::getbits()
{
    return m_passwordGenerator.getbits();
}
