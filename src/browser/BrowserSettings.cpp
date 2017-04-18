/**
 ***************************************************************************
 * @file BrowserSettings.cpp
 *
 * @original    HttpSettings.cpp
 * @brief
 *
 * Copyright (C) 2013
 *
 * @author      Francois Ferrand
 * @date        4/2013
 *
 * @modified    Sami Vänttinen
 * @date        4/2017
 ***************************************************************************
 */

#include "BrowserSettings.h"
#include "core/Config.h"

PasswordGenerator BrowserSettings::m_generator;

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
    m_generator.setLength(length);
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
    m_generator.setLength(passwordLength());
    m_generator.setCharClasses(passwordCharClasses());
    m_generator.setFlags(passwordGeneratorFlags());

    return m_generator.generatePassword();
}

int BrowserSettings::getbits()
{
    return m_generator.getbits();
}
