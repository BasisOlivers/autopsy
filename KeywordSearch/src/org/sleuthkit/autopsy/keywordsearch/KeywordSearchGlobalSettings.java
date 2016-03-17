/*
 * Autopsy Forensic Browser
 *
 * Copyright 2012-2014 Basis Technology Corp.
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

import java.beans.PropertyChangeListener;
import java.beans.PropertyChangeSupport;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;

import org.openide.util.NbBundle;
import org.openide.util.io.NbObjectInputStream;
import org.openide.util.io.NbObjectOutputStream;
import org.sleuthkit.autopsy.coreutils.Logger;
import org.sleuthkit.autopsy.coreutils.MessageNotifyUtil;
import org.sleuthkit.autopsy.coreutils.ModuleSettings;
import org.sleuthkit.autopsy.coreutils.PlatformUtil;
import org.sleuthkit.autopsy.coreutils.StringExtract;
import org.sleuthkit.autopsy.coreutils.StringExtract.StringExtractUnicodeTable.SCRIPT;
import org.sleuthkit.autopsy.keywordsearch.KeywordSearchIngestModule.UpdateFrequency;
import static org.sleuthkit.autopsy.keywordsearch.KeywordSearchList.logger;
import org.sleuthkit.datamodel.BlackboardAttribute;

//This file contains constants and settings for KeywordSearch
final class KeywordSearchGlobalSettings implements Serializable {

    private static final String KEYWORD_SERIALIZATION_FILE = "KeywordSearch.settings";
    private static final String KEYWORD_SERIALIZATION_PATH = PlatformUtil.getUserConfigDirectory() + File.separator + KEYWORD_SERIALIZATION_FILE;
    public static final String MODULE_NAME = NbBundle.getMessage(KeywordSearchGlobalSettings.class, "KeywordSearchSettings.moduleName.text");
    static final String PROPERTIES_OPTIONS = NbBundle.getMessage(KeywordSearchGlobalSettings.class, "KeywordSearchSettings.properties_options.text", MODULE_NAME);
    static final String PROPERTIES_NSRL = NbBundle.getMessage(KeywordSearchGlobalSettings.class, "KeywordSearchSettings.propertiesNSRL.text", MODULE_NAME);
    static final String PROPERTIES_SCRIPTS = NbBundle.getMessage(KeywordSearchGlobalSettings.class, "KeywordSearchSettings.propertiesScripts.text", MODULE_NAME);
    static final String SHOW_SNIPPETS = "showSnippets"; //NON-NLS
    private static final String CUR_LISTS_FILE_NAME = "keywords.xml";     //NON-NLS
    private static final String CUR_LISTS_FILE = PlatformUtil.getUserConfigDirectory() + File.separator + CUR_LISTS_FILE_NAME;
    private boolean showSnippets;
    private boolean skipKnown;
    private static final Logger logger = Logger.getLogger(KeywordSearchGlobalSettings.class.getName());
    private UpdateFrequency UpdateFreq;
    private List<StringExtract.StringExtractUnicodeTable.SCRIPT> stringExtractScripts;
    private Map<String, String> stringExtractOptions;
    private Map<String, KeywordList> keywordLists;
    private List<String> lockedLists;
    private static final long serialVersionUID = 1L;
    private transient PropertyChangeSupport changeSupport = new PropertyChangeSupport(this);
    private static KeywordSearchGlobalSettings settings;

    private KeywordSearchGlobalSettings(boolean showSnippets, boolean skipKnown, UpdateFrequency UpdateFreq, List<SCRIPT> stringExtractScripts, Map<String, String> stringExtractOptions, List<KeywordList> keywordLists) {
        this.showSnippets = showSnippets;
        this.skipKnown = skipKnown;
        this.UpdateFreq = UpdateFreq;
        this.stringExtractScripts = stringExtractScripts;
        this.stringExtractOptions = stringExtractOptions;
        this.keywordLists = new LinkedHashMap<>();
        for (KeywordList list : keywordLists) {
            this.keywordLists.put(list.getName(), list);
        }
        changeSupport = new PropertyChangeSupport(this);
    }

    private KeywordSearchGlobalSettings() {
        if (new File(KEYWORD_SERIALIZATION_PATH).exists()) {
            try {
                try (NbObjectInputStream in = new NbObjectInputStream(new FileInputStream(KEYWORD_SERIALIZATION_PATH))) {
                    KeywordSearchGlobalSettings globalSettings = (KeywordSearchGlobalSettings) in.readObject();
                    this.showSnippets = globalSettings.getShowSnippets();
                    this.skipKnown = globalSettings.getSkipKnown();
                    this.UpdateFreq = globalSettings.getUpdateFrequency();
                    this.stringExtractScripts = globalSettings.getStringExtractScripts();
                    this.stringExtractOptions = globalSettings.getStringExtractOptions();
                    this.keywordLists = new LinkedHashMap<>();
                    this.lockedLists = new ArrayList<>();
                    this.prepopulateLists();
                    for (KeywordList list : globalSettings.getKeywordLists()) {
                        this.keywordLists.put(list.getName(), list);
                    }
                    changeSupport = new PropertyChangeSupport(this);
                }
            } catch (IOException | ClassNotFoundException ex) {
                settings = new KeywordSearchGlobalSettings();
                logger.log(Level.SEVERE, "Failed to read settings from " + KEYWORD_SERIALIZATION_PATH);
            }
        } else {
            if (ModuleSettings.settingExists(PROPERTIES_NSRL, "SkipKnown")) { //NON-NLS
                this.skipKnown = Boolean.parseBoolean(ModuleSettings.getConfigSetting(PROPERTIES_NSRL, "SkipKnown"));
            } else {
                this.skipKnown = true;
            }
            if (ModuleSettings.settingExists(PROPERTIES_OPTIONS, "showSnippets")) {
                showSnippets = ModuleSettings.getConfigSetting(PROPERTIES_OPTIONS, "showSnippets").equals("true"); //NON-NLS
            } else {
                showSnippets = true;
            }
            //setting default Update Frequency
            if (ModuleSettings.settingExists(PROPERTIES_OPTIONS, "UpdateFrequency")) { //NON-NLS
                this.UpdateFreq = UpdateFrequency.valueOf(ModuleSettings.getConfigSetting(PROPERTIES_OPTIONS, "UpdateFrequency"));
            } else {
                this.UpdateFreq = UpdateFrequency.DEFAULT;
            }
            if (ModuleSettings.configExists(PROPERTIES_OPTIONS)) {
                stringExtractOptions = ModuleSettings.getConfigSettings(PROPERTIES_OPTIONS);
            }
            if (ModuleSettings.getConfigSettings(PROPERTIES_SCRIPTS) != null && !ModuleSettings.getConfigSettings(PROPERTIES_SCRIPTS).isEmpty()) {
                List<SCRIPT> scripts = new ArrayList<>();
                for (Map.Entry<String, String> kvp : ModuleSettings.getConfigSettings(PROPERTIES_SCRIPTS).entrySet()) {
                    if (kvp.getValue().equals("true")) { //NON-NLS
                        scripts.add(SCRIPT.valueOf(kvp.getKey()));
                    }
                }
                stringExtractScripts = scripts;
            }
            XmlKeywordSearchList xml = new XmlKeywordSearchList(CUR_LISTS_FILE);
            xml.reload();
            this.keywordLists = new LinkedHashMap<>();
            this.setKeywordLists(xml.getListsL());
            this.save();
        }
    }

    /**
     * Saves this settings object to disk.
     */
    synchronized private void save() {
        try (NbObjectOutputStream out = new NbObjectOutputStream(new FileOutputStream(KEYWORD_SERIALIZATION_PATH))) {
            List<KeywordList> removedLists = new ArrayList();
            for (String name : lockedLists) {
                KeywordList removed = this.keywordLists.remove(name);
                removedLists.add(removed);
            }
            out.writeObject(this);
            for (KeywordList list : removedLists) {
                keywordLists.put(list.getName(), list);
            }
        } catch (IOException ex) {
            logger.log(Level.SEVERE, "Failed to write settings to " + KEYWORD_SERIALIZATION_PATH);
        }

    }

    synchronized private void prepopulateLists() {
        if (!keywordLists.isEmpty()) {
            return;
        }
        //phone number
        List<Keyword> phones = new ArrayList<>();
        phones.add(new Keyword("[(]{0,1}\\d\\d\\d[)]{0,1}[\\.-]\\d\\d\\d[\\.-]\\d\\d\\d\\d", false, BlackboardAttribute.ATTRIBUTE_TYPE.TSK_PHONE_NUMBER)); //NON-NLS
        //phones.add(new Keyword("\\d{8,10}", false));
        //IP address
        List<Keyword> ips = new ArrayList<>();
        ips.add(new Keyword("(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])", false, BlackboardAttribute.ATTRIBUTE_TYPE.TSK_IP_ADDRESS));
        //email
        List<Keyword> emails = new ArrayList<>();
        emails.add(new Keyword("(?=.{8})[a-z0-9%+_-]+(?:\\.[a-z0-9%+_-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\\.)+[a-z]{2,4}(?<!\\.txt|\\.exe|\\.dll|\\.jpg|\\.xml)", //NON-NLS
                false, BlackboardAttribute.ATTRIBUTE_TYPE.TSK_EMAIL));
        //emails.add(new Keyword("[A-Z0-9._%-]+@[A-Z0-9.-]+\\.[A-Z]{2,4}", 
        //                       false, BlackboardAttribute.ATTRIBUTE_TYPE.TSK_EMAIL));
        //URL
        List<Keyword> urls = new ArrayList<>();
        //urls.add(new Keyword("http://|https://|^www\\.", false, BlackboardAttribute.ATTRIBUTE_TYPE.TSK_URL));
        urls.add(new Keyword("((((ht|f)tp(s?))\\://)|www\\.)[a-zA-Z0-9\\-\\.]+\\.([a-zA-Z]{2,5})(\\:[0-9]+)*(/($|[a-zA-Z0-9\\.\\,\\;\\?\\'\\\\+&amp;%\\$#\\=~_\\-]+))*", false, BlackboardAttribute.ATTRIBUTE_TYPE.TSK_URL)); //NON-NLS

        //urls.add(new Keyword("ssh://", false, BlackboardAttribute.ATTRIBUTE_TYPE.TSK_URL));
        //disable messages for harcoded/locked lists
        String name;

        name = "Phone Numbers"; //NON-NLS
        lockedLists.add(name);
        this.addKeywordList(new KeywordList(name, new Date(), new Date(), false, false, phones, true));

        name = "IP Addresses"; //NON-NLS
        lockedLists.add(name);
        addKeywordList(new KeywordList(name, new Date(), new Date(), false, false, ips, true));

        name = "Email Addresses"; //NON-NLS
        lockedLists.add(name);
        addKeywordList(new KeywordList(name, new Date(), new Date(), false, false, emails, true));

        name = "URLs"; //NON-NLS
        lockedLists.add(name);
        addKeywordList(new KeywordList(name, new Date(), new Date(), false, false, urls, true));
    }

    /**
     * Adds the property change listener from the change support
     *
     * @param listener The listener to add.
     */
    synchronized void addPropertyChangeListener(PropertyChangeListener listener) {
        changeSupport.addPropertyChangeListener(listener);
    }

    /**
     * Removes the property change listener from the change support
     *
     * @param listener The listener to remove.
     */
    synchronized void removePropertyChangeListener(PropertyChangeListener listener) {
        changeSupport.removePropertyChangeListener(listener);
    }

    /**
     * Fires the given language event
     *
     * @param event The event to fire
     */
    synchronized void fireLanguagesEvent(KeywordSearchList.LanguagesEvent event) {
        try {
            changeSupport.firePropertyChange(event.toString(), null, null);
        } catch (Exception e) {
            logger.log(Level.SEVERE, "KeywordSearchListsAbstract listener threw exception", e); //NON-NLS
        }
    }

    /**
     * Gets the global settings object.
     *
     * @return The global settings.
     */
    static synchronized KeywordSearchGlobalSettings getSettings() {
        if (settings == null) {
            settings = new KeywordSearchGlobalSettings();
        }
        return settings;
    }

    /**
     * Gets the update Frequency from KeywordSearch_Options.properties
     *
     * @return KeywordSearchIngestModule's update frequency
     */
    synchronized UpdateFrequency getUpdateFrequency() {
        return this.UpdateFreq;
    }

    /**
     * Sets the update frequency and writes to KeywordSearch_Options.properties
     *
     * @param freq Sets KeywordSearchIngestModule to this value.
     */
    synchronized void setUpdateFrequency(UpdateFrequency freq) {
        UpdateFreq = freq;
        this.save();
    }

    /**
     * Sets whether or not to skip adding known good files to the search during
     * index.
     *
     * @param skip
     */
    synchronized void setSkipKnown(boolean skip) {
        skipKnown = skip;
        this.save();
    }

    /**
     * Gets the setting for whether or not this ingest is skipping adding known
     * good files to the index.
     *
     * @return skip setting
     */
    synchronized boolean getSkipKnown() {
        return skipKnown;
    }

    /**
     * Sets what scripts to extract during ingest
     *
     * @param scripts List of scripts to extract
     */
    synchronized void setStringExtractScripts(List<StringExtract.StringExtractUnicodeTable.SCRIPT> scripts) {
        stringExtractScripts.clear();
        stringExtractScripts.addAll(scripts);
        this.save();
    }

    /**
     * Set / override string extract option
     *
     * @param key option name to set
     * @param val option value to set
     */
    synchronized void setStringExtractOption(String key, String val) {
        stringExtractOptions.put(key, val);
        this.save();
    }

    /**
     * Sets the show snippets setting.
     *
     * @param showSnippets Whether or not to show snippets
     */
    synchronized void setShowSnippets(boolean showSnippets) {
        this.showSnippets = showSnippets;
        this.save();
    }

    /**
     * Gets whether or not to show snippets.
     *
     * @return The show snippets setting
     */
    synchronized boolean getShowSnippets() {
        return this.showSnippets;
    }

    /**
     * Gets the currently set scripts to use
     *
     * @return the list of currently used script
     */
    synchronized List<SCRIPT> getStringExtractScripts() {
        return new ArrayList<>(stringExtractScripts);

    }

    /**
     * Get string extract option for the key
     *
     * @param key option name
     *
     * @return option string value, or empty string if the option is not set
     */
    synchronized String getStringExtractOption(String key) {
        return stringExtractOptions.get(key);
    }

    /**
     * Get the map of string extract options.
     *
     * @return Map<String,String> of extract options.
     */
    synchronized Map<String, String> getStringExtractOptions() {
        Map<String, String> extractOptions = new HashMap<>();
        extractOptions.putAll(this.stringExtractOptions);
        return extractOptions;
    }

    /**
     * Gets the keyword lists used by the settings.
     *
     * @return The list of keyword lists
     */
    synchronized List<KeywordList> getKeywordLists() {
        List<KeywordList> lists = new ArrayList<>();
        for (KeywordList list : this.keywordLists.values()) {
            lists.add(list);
        }
        return lists;
    }

    /**
     * Set's this setting's keyword lists to the given lists, deleting all
     * current lists.
     *
     * @param keywordLists The new keyword lists to be used
     */
    synchronized void setKeywordLists(List<KeywordList> keywordLists) {
        this.keywordLists.clear();
        for (KeywordList list : keywordLists) {
            this.keywordLists.put(list.getName(), list);
        }
        this.save();
    }

    /**
     * Adds the given keyword list to the settings. Replaces if there is a list
     * of the same name.
     *
     * @param list The list to add
     */
    synchronized void addKeywordList(KeywordList list) {
        if (!this.listExists(list.getName())) {
            this.keywordLists.put(list.getName(), list);
            try {
                changeSupport.firePropertyChange(KeywordSearchList.ListsEvt.LIST_ADDED.toString(), null, list.getName());
            } catch (Exception e) {
                logger.log(Level.SEVERE, "KeywordSearchListsAbstract listener threw exception", e); //NON-NLS
                MessageNotifyUtil.Notify.show(
                        NbBundle.getMessage(this.getClass(), "KeywordSearchListsAbstract.moduleErr"),
                        NbBundle.getMessage(this.getClass(), "KeywordSearchListsAbstract.addList.errMsg1.msg"),
                        MessageNotifyUtil.MessageType.ERROR);
            }
            this.save();
        } else {
            this.keywordLists.put(list.getName(), list);
            try {
                changeSupport.firePropertyChange(KeywordSearchList.ListsEvt.LIST_UPDATED.toString(), null, list.getName());
            } catch (Exception e) {
                logger.log(Level.SEVERE, "KeywordSearchListsAbstract listener threw exception", e); //NON-NLS
                MessageNotifyUtil.Notify.show(
                        NbBundle.getMessage(this.getClass(), "KeywordSearchListsAbstract.moduleErr"),
                        NbBundle.getMessage(this.getClass(), "KeywordSearchListsAbstract.addList.errMsg2.msg"),
                        MessageNotifyUtil.MessageType.ERROR);
            }
            this.save();
        }
    }

    /**
     * Adds the keyword lists. Replaces lists that have the same name of a given
     * list
     *
     * @param lists The lists to add to the settings
     */
    synchronized void addKeywordLists(List<KeywordList> lists) {
        for (KeywordList list : lists) {
            if (!this.listExists(list.getName())) {
                this.keywordLists.put(list.getName(), list);
                try {
                    changeSupport.firePropertyChange(KeywordSearchList.ListsEvt.LIST_ADDED.toString(), null, list.getName());
                } catch (Exception e) {
                    logger.log(Level.SEVERE, "KeywordSearchListsAbstract listener threw exception", e); //NON-NLS
                    MessageNotifyUtil.Notify.show(
                            NbBundle.getMessage(this.getClass(), "KeywordSearchListsAbstract.moduleErr"),
                            NbBundle.getMessage(this.getClass(), "KeywordSearchListsAbstract.addList.errMsg1.msg"),
                            MessageNotifyUtil.MessageType.ERROR);
                }
            } else {
                this.keywordLists.put(list.getName(), list);
                try {
                    changeSupport.firePropertyChange(KeywordSearchList.ListsEvt.LIST_UPDATED.toString(), null, list.getName());
                } catch (Exception e) {
                    logger.log(Level.SEVERE, "KeywordSearchListsAbstract listener threw exception", e); //NON-NLS
                    MessageNotifyUtil.Notify.show(
                            NbBundle.getMessage(this.getClass(), "KeywordSearchListsAbstract.moduleErr"),
                            NbBundle.getMessage(this.getClass(), "KeywordSearchListsAbstract.addList.errMsg2.msg"),
                            MessageNotifyUtil.MessageType.ERROR);
                }
            }
        }
        this.save();
    }

    /**
     * Gets the keyword list of the given name
     *
     * @param name The name of the keyword list to get
     *
     * @return The keyword list of the given name, null if it doesn't exist
     */
    synchronized KeywordList getList(String name) {
        return this.keywordLists.get(name);
    }

    /**
     * Deletes the list with the given name
     *
     * @param name The name of the list to delete
     */
    synchronized void deleteList(String name) {
        this.keywordLists.remove(name);
    }

    /**
     * Checks if a list with the given name exists
     *
     * @param name The name of the keyword list
     *
     * @return true if the list exists, false otherwise
     */
    synchronized boolean listExists(String name) {
        return this.keywordLists.containsKey(name);
    }
}
