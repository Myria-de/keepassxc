/*
 *  Copyright (C) 2023 KeePassXC Team <team@keepassxc.org>
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

#include "ReportsWidgetPasskeys.h"
#include "ui_ReportsWidgetPasskeys.h"

#include "browser/BrowserService.h"
#include "core/AsyncTask.h"
#include "core/Group.h"
#include "core/Metadata.h"
#include "gui/GuiTools.h"
#include "gui/Icons.h"
#include "gui/styles/StateColorPalette.h"
#include "gui/webauthn/PasskeyExporter.h"
#include "gui/webauthn/PasskeyImporter.h"

#include <QMenu>
#include <QShortcut>
#include <QSortFilterProxyModel>
#include <QStandardItemModel>

namespace
{
    class PasskeyList
    {
    public:
        struct Item
        {
            QPointer<Group> group;
            QPointer<Entry> entry;
            bool exclude = false;

            Item(Group* g, Entry* e)
                : group(g)
                , entry(e)
                , exclude(e->excludeFromReports())
            {
            }
        };

        explicit PasskeyList(const QSharedPointer<Database>&);

        const QList<QSharedPointer<Item>>& items() const
        {
            return m_items;
        }

    private:
        QSharedPointer<Database> m_db;
        QList<QSharedPointer<Item>> m_items;
    };
} // namespace

PasskeyList::PasskeyList(const QSharedPointer<Database>& db)
    : m_db(db)
{
    for (auto group : db->rootGroup()->groupsRecursive(true)) {
        // Skip recycle bin
        if (group->isRecycled()) {
            continue;
        }

        for (auto entry : group->entries()) {
            if (entry->isRecycled() || !entry->attachments()->hasKey(BrowserService::WEBAUTHN_KEY_FILENAME)) {
                continue;
            }

            const auto item = QSharedPointer<Item>(new Item(group, entry));
            m_items.append(item);
        }
    }
}

ReportsWidgetPasskeys::ReportsWidgetPasskeys(QWidget* parent)
    : QWidget(parent)
    , m_ui(new Ui::ReportsWidgetPasskeys())
    , m_referencesModel(new QStandardItemModel(this))
    , m_modelProxy(new QSortFilterProxyModel(this))
{
    m_ui->setupUi(this);

    m_modelProxy->setSourceModel(m_referencesModel.data());
    m_modelProxy->setSortLocaleAware(true);
    m_ui->passkeysTableView->setModel(m_modelProxy.data());
    m_ui->passkeysTableView->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
    m_ui->passkeysTableView->verticalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);

    connect(m_ui->passkeysTableView, SIGNAL(customContextMenuRequested(QPoint)), SLOT(customMenuRequested(QPoint)));
    connect(m_ui->passkeysTableView, SIGNAL(doubleClicked(QModelIndex)), SLOT(emitEntryActivated(QModelIndex)));
    connect(m_ui->passkeysTableView->selectionModel(),
            SIGNAL(selectionChanged(QItemSelection, QItemSelection)),
            this,
            SLOT(selectionChanged()));
    connect(m_ui->excludeExpired, SIGNAL(stateChanged(int)), this, SLOT(updateEntries()));
    connect(m_ui->exportButton, SIGNAL(clicked(bool)), this, SLOT(exportPasskey()));
    connect(m_ui->importButton, SIGNAL(clicked(bool)), this, SLOT(importPasskey()));

    m_ui->exportButton->setEnabled(false);

    new QShortcut(Qt::Key_Delete, this, SLOT(deleteSelectedEntries()));
}

ReportsWidgetPasskeys::~ReportsWidgetPasskeys()
{
}

void ReportsWidgetPasskeys::addPasskeyRow(Group* group, Entry* entry, bool excluded)
{
    StateColorPalette statePalette;

    auto urlList = entry->getAllUrls();
    auto urlToolTip = tr("List of entry URLs");

    auto title = entry->title();
    if (excluded) {
        title.append(tr(" (Excluded)"));
    }

    auto row = QList<QStandardItem*>();
    row << new QStandardItem(Icons::entryIconPixmap(entry), title);
    row << new QStandardItem(Icons::groupIconPixmap(group), group->hierarchy().join("/"));
    row << new QStandardItem(entry->username());
    row << new QStandardItem(urlList.join('\n'));

    // Set tooltips
    row[2]->setToolTip(urlToolTip);
    if (excluded) {
        row[0]->setToolTip(tr("This entry is being excluded from reports"));
    }

    // Store entry pointer per table row (used in double click handler)
    m_referencesModel->appendRow(row);
    m_rowToEntry.append({group, entry});
}

void ReportsWidgetPasskeys::loadSettings(QSharedPointer<Database> db)
{
    m_db = std::move(db);
    m_entriesUpdated = false;
    m_referencesModel->clear();
    m_rowToEntry.clear();

    auto row = QList<QStandardItem*>();
    row << new QStandardItem(tr("Please wait, list of entries with Passkeys is being updated…"));
    m_referencesModel->appendRow(row);
}

void ReportsWidgetPasskeys::showEvent(QShowEvent* event)
{
    QWidget::showEvent(event);

    if (!m_entriesUpdated) {
        // Perform stats calculation on next event loop to allow widget to appear
        m_entriesUpdated = true;
        QTimer::singleShot(0, this, SLOT(updateEntries()));
    }
}

void ReportsWidgetPasskeys::updateEntries()
{
    m_referencesModel->clear();

    // Perform the statistics check
    const QScopedPointer<PasskeyList> browserStatistics(
        AsyncTask::runAndWaitForFuture([this] { return new PasskeyList(m_db); }));

    const auto showExcluded = !m_ui->excludeExpired->isChecked();

    // Display the entries
    m_rowToEntry.clear();
    for (const auto& item : browserStatistics->items()) {
        auto excluded = item->exclude || (item->entry->isExpired() && m_ui->excludeExpired->isChecked());
        if (excluded && !showExcluded) {
            // Exclude this entry from the report
            continue;
        }

        // Show the entry in the report
        addPasskeyRow(item->group, item->entry, item->exclude);
    }

    // Set the table header
    if (m_referencesModel->rowCount() == 0) {
        m_referencesModel->setHorizontalHeaderLabels(QStringList() << tr("No entries with Passkeys."));
    } else {
        m_referencesModel->setHorizontalHeaderLabels(QStringList()
                                                     << tr("Title") << tr("Path") << tr("Username") << tr("URLs"));
        m_ui->passkeysTableView->sortByColumn(0, Qt::AscendingOrder);
    }

    m_ui->passkeysTableView->resizeColumnsToContents();
}

void ReportsWidgetPasskeys::emitEntryActivated(const QModelIndex& index)
{
    if (!index.isValid()) {
        return;
    }

    auto mappedIndex = m_modelProxy->mapToSource(index);
    const auto row = m_rowToEntry[mappedIndex.row()];
    const auto group = row.first;
    const auto entry = row.second;

    if (group && entry) {
        emit entryActivated(const_cast<Entry*>(entry));
    }
}

void ReportsWidgetPasskeys::customMenuRequested(QPoint pos)
{
    auto selected = m_ui->passkeysTableView->selectionModel()->selectedRows();
    if (selected.isEmpty()) {
        return;
    }

    // Create the context menu
    const auto menu = new QMenu(this);

    // Create the "edit entry" menu item (only if 1 row is selected)
    if (selected.size() == 1) {
        const auto edit = new QAction(icons()->icon("entry-edit"), tr("Edit Entry…"), this);
        menu->addAction(edit);
        connect(edit, &QAction::triggered, edit, [this, selected] {
            auto row = m_modelProxy->mapToSource(selected[0]).row();
            auto entry = m_rowToEntry[row].second;
            emit entryActivated(entry);
        });
    }

    // Create the "delete entry" menu item
    const auto delEntry = new QAction(icons()->icon("entry-delete"), tr("Delete Entry(s)…", "", selected.size()), this);
    menu->addAction(delEntry);
    connect(delEntry, &QAction::triggered, this, &ReportsWidgetPasskeys::deleteSelectedEntries);

    // Create the "exclude from reports" menu item
    const auto exclude = new QAction(icons()->icon("reports-exclude"), tr("Exclude from reports"), this);

    bool isExcluded = false;
    for (auto index : selected) {
        auto row = m_modelProxy->mapToSource(index).row();
        auto entry = m_rowToEntry[row].second;
        if (entry && entry->excludeFromReports()) {
            // If at least one entry is excluded switch to inclusion
            isExcluded = true;
            break;
        }
    }
    exclude->setCheckable(true);
    exclude->setChecked(isExcluded);

    menu->addAction(exclude);
    connect(exclude, &QAction::toggled, exclude, [this, selected](bool state) {
        for (auto index : selected) {
            auto row = m_modelProxy->mapToSource(index).row();
            auto entry = m_rowToEntry[row].second;
            if (entry) {
                entry->setExcludeFromReports(state);
            }
        }
        updateEntries();
    });

    // Show the context menu
    menu->popup(m_ui->passkeysTableView->viewport()->mapToGlobal(pos));
}

void ReportsWidgetPasskeys::saveSettings()
{
    // Nothing to do - the tab is passive
}

void ReportsWidgetPasskeys::deleteSelectedEntries()
{
    auto selectedEntries = getSelectedEntries();
    bool permanent = !m_db->metadata()->recycleBinEnabled();

    if (GuiTools::confirmDeleteEntries(this, selectedEntries, permanent)) {
        GuiTools::deleteEntriesResolveReferences(this, selectedEntries, permanent);
    }

    updateEntries();
}

QList<Entry*> ReportsWidgetPasskeys::getSelectedEntries()
{
    QList<Entry*> selectedEntries;
    for (auto index : m_ui->passkeysTableView->selectionModel()->selectedRows()) {
        auto row = m_modelProxy->mapToSource(index).row();
        auto entry = m_rowToEntry[row].second;
        if (entry) {
            selectedEntries << entry;
        }
    }

    return selectedEntries;
}

void ReportsWidgetPasskeys::selectionChanged()
{
    m_ui->exportButton->setEnabled(!m_ui->passkeysTableView->selectionModel()->selectedIndexes().isEmpty());
}

void ReportsWidgetPasskeys::importPasskey()
{
    PasskeyImporter passkeyImporter;
    passkeyImporter.importPasskey(m_db);

    updateEntries();
}

void ReportsWidgetPasskeys::exportPasskey()
{
    PasskeyExporter passkeyExporter;
    passkeyExporter.showExportDialog(getSelectedEntries());
}
