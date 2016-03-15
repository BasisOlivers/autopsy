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

import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;

import org.openide.util.NbBundle;
import org.sleuthkit.autopsy.coreutils.Logger;
import org.sleuthkit.autopsy.coreutils.ModuleSettings;
import org.sleuthkit.autopsy.coreutils.StringExtract;
import org.sleuthkit.autopsy.coreutils.StringExtract.StringExtractUnicodeTable.SCRIPT;
import org.sleuthkit.autopsy.keywordsearch.KeywordSearchIngestModule.UpdateFrequency;

//This file contains constants and settings for KeywordSearch
class KeywordSearchGlobalSettings implements Serializable {

    public static final String MODULE_NAME = NbBundle.getMessage(KeywordSearchGlobalSettings.class, "KeywordSearchSettings.moduleName.text");
    static final String PROPERTIES_OPTIONS = NbBundle.getMessage(KeywordSearchGlobalSettings.class, "KeywordSearchSettings.properties_options.text", MODULE_NAME);
    static final String PROPERTIES_NSRL = NbBundle.getMessage(KeywordSearchGlobalSettings.class, "KeywordSearchSettings.propertiesNSRL.text", MODULE_NAME);
    static final String PROPERTIES_SCRIPTS = NbBundle.getMessage(KeywordSearchGlobalSettings.class, "KeywordSearchSettings.propertiesScripts.text", MODULE_NAME);
    static final String SHOW_SNIPPETS = "showSnippets"; //NON-NLS
    private boolean showSnippets;
    private boolean skipKnown;
    private static final Logger logger = Logger.getLogger(KeywordSearchGlobalSettings.class.getName());
    private UpdateFrequency UpdateFreq;
    private List<StringExtract.StringExtractUnicodeTable.SCRIPT> stringExtractScripts;
    private Map<String, String> stringExtractOptions;
    private List<KeywordList> keywordLists;
    private static final long serialVersionUID = 1L;

    KeywordSearchGlobalSettings(boolean showSnippets, boolean skipKnown, UpdateFrequency UpdateFreq, List<SCRIPT> stringExtractScripts, Map<String, String> stringExtractOptions, List<KeywordList> keywordLists) {
        this.showSnippets = showSnippets;
        this.skipKnown = skipKnown;
        this.UpdateFreq = UpdateFreq;
        this.stringExtractScripts = stringExtractScripts;
        this.stringExtractOptions = stringExtractOptions;
        this.keywordLists = keywordLists;
    }

    KeywordSearchGlobalSettings() {
        showSnippets = true;
        skipKnown = true;
        UpdateFreq = UpdateFrequency.DEFAULT;
        stringExtractScripts = new ArrayList<>();
        stringExtractOptions = new HashMap<>();
        keywordLists = new ArrayList<>();
    }

    /**
     * Gets the update Frequency from KeywordSearch_Options.properties
     *
     * @return KeywordSearchIngestModule's update frequency
     */
    UpdateFrequency getUpdateFrequency() {
        return this.UpdateFreq;
    }

    /**
     * Sets the update frequency and writes to KeywordSearch_Options.properties
     *
     * @param freq Sets KeywordSearchIngestModule to this value.
     */
    void setUpdateFrequency(UpdateFrequency freq) {
        UpdateFreq = freq;
        GlobalSettingsManager.getInstance().save(this);
    }

    /**
     * Sets whether or not to skip adding known good files to the search during
     * index.
     *
     * @param skip
     */
    void setSkipKnown(boolean skip) {
        skipKnown = skip;
        GlobalSettingsManager.getInstance().save(this);
    }

    /**
     * Gets the setting for whether or not this ingest is skipping adding known
     * good files to the index.
     *
     * @return skip setting
     */
    boolean getSkipKnown() {
        return skipKnown;
    }

    /**
     * Sets what scripts to extract during ingest
     *
     * @param scripts List of scripts to extract
     */
    void setStringExtractScripts(List<StringExtract.StringExtractUnicodeTable.SCRIPT> scripts) {
        stringExtractScripts.clear();
        stringExtractScripts.addAll(scripts);
        GlobalSettingsManager.getInstance().save(this);
    }

    /**
     * Set / override string extract option
     *
     * @param key option name to set
     * @param val option value to set
     */
    void setStringExtractOption(String key, String val) {
        stringExtractOptions.put(key, val);
        GlobalSettingsManager.getInstance().save(this);
    }

    void setShowSnippets(boolean showSnippets) {
        this.showSnippets = showSnippets;
        GlobalSettingsManager.getInstance().save(this);
    }

    boolean getShowSnippets() {
        return this.showSnippets;
    }

    /**
     * gets the currently set scripts to use
     *
     * @return the list of currently used script
     */
    List<SCRIPT> getStringExtractScripts() {
        return new ArrayList<>(stringExtractScripts);

    }

    /**
     * get string extract option for the key
     *
     * @param key option name
     *
     * @return option string value, or empty string if the option is not set
     */
    String getStringExtractOption(String key) {
        return stringExtractOptions.get(key);
    }

    /**
     * get the map of string extract options.
     *
     * @return Map<String,String> of extract options.
     */
    Map<String, String> getStringExtractOptions() {
        Map<String, String> extractOptions = new HashMap<>();
        extractOptions.putAll(this.stringExtractOptions);
        return extractOptions;
    }

    /**
     * @return the keywordLists
     */
    List<KeywordList> getKeywordLists() {
        return keywordLists;
    }

    /**
     * @param keywordLists the keywordLists to set
     */
    void setKeywordLists(List<KeywordList> keywordLists) {
        this.keywordLists = keywordLists;
        GlobalSettingsManager.getInstance().save(this);
    }

    void addKeywordList(KeywordList list) {
        this.keywordLists.add(list);
        GlobalSettingsManager.getInstance().save(this);
    }

    KeywordList getList(String name) {
        for (KeywordList list : this.keywordLists) {
            if (list.getName().equals(name)) {
                return list;
            }
        }
        return null;
    }

    void deleteList(String name) {
        for (KeywordList list : this.keywordLists) {
            if(list.getName().equals(name)) {
                this.keywordLists.remove(list);
                GlobalSettingsManager.getInstance().save(this);
            }
        }
    }
}
