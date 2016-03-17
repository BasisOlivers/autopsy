/*
 * Autopsy Forensic Browser
 * 
 * Copyright 2011-2014 Basis Technology Corp.
 * Contact: carrier <at> sleuthkit <dot> org
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.sleuthkit.autopsy.keywordsearch;

import java.awt.event.KeyEvent;
import java.io.File;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import org.openide.util.NbBundle;
import org.sleuthkit.autopsy.coreutils.Logger;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import javax.swing.event.ListSelectionListener;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.table.AbstractTableModel;
import org.sleuthkit.autopsy.corecomponents.OptionsPanel;

/**
 * A panel to manage all keyword lists created/imported in Autopsy.
 */
class GlobalListsManagementPanel extends javax.swing.JPanel implements OptionsPanel {

    private Logger logger = Logger.getLogger(GlobalListsManagementPanel.class.getName());
    private KeywordListTableModel tableModel;

    GlobalListsManagementPanel() {
        tableModel = new KeywordListTableModel();
        initComponents();
        customizeComponents();
    }

    private void customizeComponents() {
        listsTable.setAutoscrolls(true);
        listsTable.setTableHeader(null);
        listsTable.setShowHorizontalLines(false);
        listsTable.setShowVerticalLines(false);

        listsTable.getParent().setBackground(listsTable.getBackground());

        listsTable.setCellSelectionEnabled(false);
        listsTable.setRowSelectionAllowed(true);
        tableModel.resync();

        /*
         * XmlKeywordSearchList.getCurrent().addPropertyChangeListener(new
         * PropertyChangeListener() {
         *
         * @Override public void propertyChange(PropertyChangeEvent evt) { if
         * (evt.getPropertyName().equals(XmlKeywordSearchList.ListsEvt.LIST_ADDED.toString()))
         * { tableModel.resync(); for(int i = 0; i<listsTable.getRowCount();
         * i++) { String name = (String) listsTable.getValueAt(i, 0);
         * if(((String) evt.getNewValue()).equals(name)) {
         * listsTable.getSelectionModel().setSelectionInterval(i, i); } } } else
         * if
         * (evt.getPropertyName().equals(XmlKeywordSearchList.ListsEvt.LIST_DELETED.toString()))
         * { tableModel.resync(); if(listsTable.getRowCount() > 0) {
         * listsTable.getSelectionModel().setSelectionInterval(0, 0); } else {
         * listsTable.getSelectionModel().clearSelection(); } } } });
         */
    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jScrollPane1 = new javax.swing.JScrollPane();
        listsTable = new javax.swing.JTable();
        newListButton = new javax.swing.JButton();
        importButton = new javax.swing.JButton();
        keywordListsLabel = new javax.swing.JLabel();

        setMinimumSize(new java.awt.Dimension(250, 0));
        setPreferredSize(new java.awt.Dimension(250, 492));

        jScrollPane1.setPreferredSize(new java.awt.Dimension(200, 402));

        listsTable.setModel(tableModel);
        listsTable.setShowHorizontalLines(false);
        listsTable.setShowVerticalLines(false);
        listsTable.getTableHeader().setReorderingAllowed(false);
        listsTable.addKeyListener(new java.awt.event.KeyAdapter() {
            public void keyPressed(java.awt.event.KeyEvent evt) {
                listsTableKeyPressed(evt);
            }
        });
        jScrollPane1.setViewportView(listsTable);

        newListButton.setIcon(new javax.swing.ImageIcon(getClass().getResource("/org/sleuthkit/autopsy/keywordsearch/new16.png"))); // NOI18N NON-NLS
        newListButton.setText(org.openide.util.NbBundle.getMessage(GlobalListsManagementPanel.class, "KeywordSearchListsManagementPanel.newListButton.text")); // NOI18N
        newListButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                newListButtonActionPerformed(evt);
            }
        });

        importButton.setIcon(new javax.swing.ImageIcon(getClass().getResource("/org/sleuthkit/autopsy/keywordsearch/import16.png"))); // NOI18N NON-NLS
        importButton.setText(org.openide.util.NbBundle.getMessage(GlobalListsManagementPanel.class, "KeywordSearchListsManagementPanel.importButton.text")); // NOI18N
        importButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                importButtonActionPerformed(evt);
            }
        });

        keywordListsLabel.setText(org.openide.util.NbBundle.getMessage(GlobalListsManagementPanel.class, "KeywordSearchListsManagementPanel.keywordListsLabel.text")); // NOI18N

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(this);
        this.setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jScrollPane1, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addGroup(layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(keywordListsLabel)
                            .addGroup(layout.createSequentialGroup()
                                .addComponent(newListButton, javax.swing.GroupLayout.PREFERRED_SIZE, 114, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addGap(18, 18, 18)
                                .addComponent(importButton, javax.swing.GroupLayout.PREFERRED_SIZE, 126, javax.swing.GroupLayout.PREFERRED_SIZE)))
                        .addGap(0, 0, Short.MAX_VALUE)))
                .addContainerGap())
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(keywordListsLabel)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jScrollPane1, javax.swing.GroupLayout.DEFAULT_SIZE, 414, Short.MAX_VALUE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(newListButton)
                    .addComponent(importButton))
                .addContainerGap())
        );
    }// </editor-fold>//GEN-END:initComponents

    private void newListButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_newListButtonActionPerformed
        KeywordSearchGlobalSettings settings = KeywordSearchGlobalSettings.getSettings();
        String listName = (String) JOptionPane.showInputDialog(null, NbBundle.getMessage(this.getClass(), "KeywordSearch.newKwListTitle"),
                NbBundle.getMessage(this.getClass(), "KeywordSearch.newKeywordListMsg"), JOptionPane.PLAIN_MESSAGE, null, null, "");
        if (listName == null || listName.trim().equals("")) {
            return;
        }
        boolean shouldAdd = false;
        boolean locked = false;
        if (settings.getList(listName) != null) {
            if (settings.getList(listName).isLocked()) {
                locked = true;
                boolean replace = KeywordSearchUtil.displayConfirmDialog(
                        NbBundle.getMessage(this.getClass(), "KeywordSearch.newKeywordListMsg"),
                        NbBundle.getMessage(this.getClass(), "KeywordSearchListsManagementPanel.newKeywordListDescription", listName),
                        KeywordSearchUtil.DIALOG_MESSAGE_TYPE.WARN);
                if (replace) {
                    shouldAdd = true;
                }
            } else {
                boolean replace = KeywordSearchUtil.displayConfirmDialog(
                        NbBundle.getMessage(this.getClass(), "KeywordSearch.newKeywordListMsg"),
                        NbBundle.getMessage(this.getClass(), "KeywordSearchListsManagementPanel.newKeywordListDescription2", listName),
                        KeywordSearchUtil.DIALOG_MESSAGE_TYPE.WARN);
                if (replace) {
                    shouldAdd = true;
                }
            }
        } else {
            shouldAdd = true;
        }
        if (shouldAdd) {
            settings.addKeywordList(new KeywordList(listName, new Date(), new Date(), true, true, new ArrayList<Keyword>(), locked));
        }
        tableModel.resync();

        //This loop selects the recently ADDED keywordslist in the JTable
        for (int i = 0; i < listsTable.getRowCount(); i++) {
            if (listsTable.getValueAt(i, 0).equals(listName)) {
                listsTable.getSelectionModel().addSelectionInterval(i, i);
            }
        }
    }//GEN-LAST:event_newListButtonActionPerformed

    private void importButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_importButtonActionPerformed

        JFileChooser chooser = new JFileChooser();
        final String[] AUTOPSY_EXTENSIONS = new String[]{"xml"}; //NON-NLS
        final String[] ENCASE_EXTENSIONS = new String[]{"txt"}; //NON-NLS
        FileNameExtensionFilter autopsyFilter = new FileNameExtensionFilter(
                NbBundle.getMessage(this.getClass(), "KeywordSearchListsManagementPanel.fileExtensionFilterLbl"), AUTOPSY_EXTENSIONS);
        FileNameExtensionFilter encaseFilter = new FileNameExtensionFilter(
                NbBundle.getMessage(this.getClass(), "KeywordSearchListsManagementPanel.fileExtensionFilterLb2"), ENCASE_EXTENSIONS);
        chooser.addChoosableFileFilter(autopsyFilter);
        chooser.addChoosableFileFilter(encaseFilter);
        chooser.setAcceptAllFileFilterUsed(false);
        chooser.setFileSelectionMode(JFileChooser.FILES_ONLY);

        String listName = null;
        int returnVal = chooser.showOpenDialog(this);
        if (returnVal == JFileChooser.APPROVE_OPTION) {
            File selFile = chooser.getSelectedFile();
            if (selFile == null) {
                return;
            }

            //force append extension if not given
            String fileAbs = selFile.getAbsolutePath();

            final KeywordSearchList reader;

            if (KeywordSearchUtil.isXMLList(fileAbs)) {
                reader = new XmlKeywordSearchList(fileAbs);
            } else {
                reader = new EnCaseKeywordSearchList(fileAbs);
            }

            if (!reader.load()) {
                KeywordSearchUtil.displayDialog(
                        NbBundle.getMessage(this.getClass(), "KeywordSearch.listImportFeatureTitle"), NbBundle.getMessage(this.getClass(), "KeywordSearch.importListFileDialogMsg", fileAbs), KeywordSearchUtil.DIALOG_MESSAGE_TYPE.ERROR);
                return;
            }

            List<KeywordList> toImport = reader.getListsL();
            List<KeywordList> toImportConfirmed = new ArrayList<KeywordList>();

            final KeywordSearchGlobalSettings settings = KeywordSearchGlobalSettings.getSettings();

            for (KeywordList list : toImport) {
                //check name collisions
                listName = list.getName();
                if (settings.getList(listName) != null) {
                    Object[] options = {NbBundle.getMessage(this.getClass(), "KeywordSearch.yesOwMsg"),
                        NbBundle.getMessage(this.getClass(), "KeywordSearch.noSkipMsg"),
                        NbBundle.getMessage(this.getClass(), "KeywordSearch.cancelImportMsg")};
                    int choice = JOptionPane.showOptionDialog(this,
                            NbBundle.getMessage(this.getClass(), "KeywordSearch.overwriteListPrompt", listName),
                            NbBundle.getMessage(this.getClass(), "KeywordSearch.importOwConflict"),
                            JOptionPane.YES_NO_CANCEL_OPTION,
                            JOptionPane.QUESTION_MESSAGE,
                            null,
                            options,
                            options[0]);
                    if (choice == JOptionPane.OK_OPTION) {
                        toImportConfirmed.add(list);
                    } else if (choice == JOptionPane.CANCEL_OPTION) {
                        break;
                    }

                } else {
                    //no conflict
                    toImportConfirmed.add(list);
                }

            }

            if (toImportConfirmed.isEmpty()) {
                return;
            }
            settings.addKeywordLists(toImportConfirmed);

        }
        tableModel.resync();

        //This loop selects the recently IMPORTED keywordslist in the JTable
        if (listName != null) {
            for (int i = 0; i < listsTable.getRowCount(); i++) {
                if (listsTable.getValueAt(i, 0).equals(listName)) {
                    listsTable.getSelectionModel().addSelectionInterval(i, i);
                }
            }
        }
    }//GEN-LAST:event_importButtonActionPerformed
    private void listsTableKeyPressed(java.awt.event.KeyEvent evt) {//GEN-FIRST:event_listsTableKeyPressed
        if (evt.getKeyCode() == KeyEvent.VK_DELETE) {
            int[] selected = listsTable.getSelectedRows();
            if (selected.length == 0) {
                return;
            } else if (KeywordSearchUtil.displayConfirmDialog(NbBundle.getMessage(this.getClass(), "KeywordSearchConfigurationPanel1.customizeComponents.title"), NbBundle.getMessage(this.getClass(), "KeywordSearchConfigurationPanel1.customizeComponents.body"), KeywordSearchUtil.DIALOG_MESSAGE_TYPE.WARN)) {
                String listName = (String) listsTable.getModel().getValueAt(selected[0], 0);
                KeywordSearchGlobalSettings.getSettings().deleteList(listName);
            } else {
                return;
            }
        }
        tableModel.resync();
    }//GEN-LAST:event_listsTableKeyPressed

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton importButton;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JLabel keywordListsLabel;
    private javax.swing.JTable listsTable;
    private javax.swing.JButton newListButton;
    // End of variables declaration//GEN-END:variables

    @Override
    public void store() {
        // Implemented by parent panel
    }

    @Override
    public void load() {
        listsTable.clearSelection();
    }

    void resync() {
        tableModel.resync();
    }

    private class KeywordListTableModel extends AbstractTableModel {

        private KeywordSearchGlobalSettings settings = KeywordSearchGlobalSettings.getSettings();

        @Override
        public int getColumnCount() {
            return 1;
        }

        @Override
        public int getRowCount() {
            List<KeywordList> totalLists = settings.getKeywordLists();
            int unlockedCount = 0;
            for (KeywordList list : totalLists) {
                if (!list.isLocked()) {
                    unlockedCount++;
                }
            }
            return unlockedCount;
        }

        @Override
        public String getColumnName(int column) {
            return NbBundle.getMessage(this.getClass(), "KeywordSearchListsManagementPanel.getColName.text");
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            List<KeywordList> totalLists = settings.getKeywordLists();
            List<KeywordList> unlockedLists = new ArrayList<KeywordList>();
            for (KeywordList list : totalLists) {
                if (!list.isLocked()) {
                    unlockedLists.add(list);
                }
            }
            return unlockedLists.get(rowIndex).getName();
        }

        @Override
        public boolean isCellEditable(int rowIndex, int columnIndex) {
            return false;
        }

        @Override
        public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
            throw new UnsupportedOperationException(
                    NbBundle.getMessage(this.getClass(), "KeywordSearchListsManagementPanel.setValueAt.exception.msg"));
        }

        @Override
        public Class<?> getColumnClass(int c) {
            return getValueAt(0, c).getClass();
        }

        //delete selected from handle, events are fired from the handle
        void deleteSelected(int[] selected) {
            List<String> toDel = new ArrayList<>();
            for (int i = 0; i < selected.length; i++) {
                toDel.add((String) getValueAt(0, selected[i]));
            }
            for (String del : toDel) {
                settings.deleteList(del);
            }
        }

        //resync model from handle, then update table
        void resync() {
            fireTableDataChanged();
        }
    }

    void addListSelectionListener(ListSelectionListener l) {
        listsTable.getSelectionModel().addListSelectionListener(l);
    }
}
