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

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.openide.util.NbBundle;
import org.openide.util.io.NbObjectInputStream;
import org.openide.util.io.NbObjectOutputStream;
import org.sleuthkit.autopsy.coreutils.ModuleSettings;
import org.sleuthkit.autopsy.coreutils.PlatformUtil;
import org.sleuthkit.autopsy.coreutils.StringExtract;
import org.sleuthkit.autopsy.coreutils.StringExtract.StringExtractUnicodeTable.SCRIPT;
import org.sleuthkit.autopsy.keywordsearch.KeywordSearchIngestModule.UpdateFrequency;

class GlobalSettingsManager {

    public static final String MODULE_NAME = NbBundle.getMessage(GlobalSettingsManager.class, "KeywordSearchSettings.moduleName.text");
    static final String PROPERTIES_OPTIONS = NbBundle.getMessage(GlobalSettingsManager.class, "KeywordSearchSettings.properties_options.text", MODULE_NAME);
    static final String PROPERTIES_NSRL = NbBundle.getMessage(GlobalSettingsManager.class, "KeywordSearchSettings.propertiesNSRL.text", MODULE_NAME);
    static final String PROPERTIES_SCRIPTS = NbBundle.getMessage(GlobalSettingsManager.class, "KeywordSearchSettings.propertiesScripts.text", MODULE_NAME);

    private static GlobalSettingsManager currInstance;
    private static final long serialVersionUID = 1L;
    private KeywordSearchGlobalSettings settings;
    private static final String KEYWORD_SERIALIZATION_FILE = "KeywordSearch.settings";
    private static final String KEYWORD_SERIALIZATION_PATH = PlatformUtil.getUserConfigDirectory() + File.separator + KEYWORD_SERIALIZATION_FILE;

    private GlobalSettingsManager() throws GlobalSettingsManagerException {
        if (new File(KEYWORD_SERIALIZATION_PATH).exists()) {
            try {
                try (NbObjectInputStream in = new NbObjectInputStream(new FileInputStream(KEYWORD_SERIALIZATION_PATH))) {
                    settings = (KeywordSearchGlobalSettings) in.readObject();
                }
            } catch (IOException | ClassNotFoundException ex) {
                throw new GlobalSettingsManagerException(String.format("Failed to read settings from %s", KEYWORD_SERIALIZATION_PATH), ex);
            }
        } else {
            //setting default NSRL
            boolean skipKnown;
            boolean showSnippets;
            UpdateFrequency frequency;
            Map<String, String> stringExtractOptions = new HashMap<>();
            List<StringExtract.StringExtractUnicodeTable.SCRIPT> stringExtractScripts = new ArrayList<>();
            List<KeywordList> keywordLists;
            if (ModuleSettings.settingExists(PROPERTIES_NSRL, "SkipKnown")) { //NON-NLS
                skipKnown = Boolean.parseBoolean(ModuleSettings.getConfigSetting(PROPERTIES_NSRL, "SkipKnown"));
            } else {
                skipKnown = true;
            }
            if (ModuleSettings.settingExists(PROPERTIES_OPTIONS, "showSnippets")) {
                showSnippets = ModuleSettings.getConfigSetting(PROPERTIES_OPTIONS, "showSnippets").equals("true"); //NON-NLS
            } else {
                showSnippets = true;
            }
            //setting default Update Frequency
            if (ModuleSettings.settingExists(PROPERTIES_OPTIONS, "UpdateFrequency")) { //NON-NLS
                frequency = UpdateFrequency.valueOf(ModuleSettings.getConfigSetting(PROPERTIES_OPTIONS, "UpdateFrequency"));
            }
            else {
                frequency = UpdateFrequency.DEFAULT;
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
            XmlKeywordSearchList xml = XmlKeywordSearchList.getCurrent();
            xml.reload();
            keywordLists = xml.getListsL();
            this.settings = new KeywordSearchGlobalSettings(showSnippets, skipKnown, frequency, stringExtractScripts, stringExtractOptions, keywordLists);
            this.save(settings);
        }
    }

    static synchronized GlobalSettingsManager getInstance() throws GlobalSettingsManagerException {
        if (currInstance == null) {
            currInstance = new GlobalSettingsManager();
        }
        return currInstance;
    }

    /**
     * @return the settings
     */
    KeywordSearchGlobalSettings getSettings() {
        return settings;
    }
    
    synchronized void save(KeywordSearchGlobalSettings settings) throws GlobalSettingsManagerException {
         try (NbObjectOutputStream out = new NbObjectOutputStream(new FileOutputStream(KEYWORD_SERIALIZATION_PATH))) {
            out.writeObject(settings);
            this.settings = settings;
        } catch (IOException ex) {
            throw new GlobalSettingsManagerException(String.format("Failed to write settings to %s", KEYWORD_SERIALIZATION_PATH), ex);
        }

    }

    /**
     * Used to translate more implementation-details-specific exceptions (which
     * are logged by this class) into more generic exceptions for propagation to
     * clients of the user-defined file types manager.
     */
    static class GlobalSettingsManagerException extends Exception {

        private static final long serialVersionUID = 1L;

        GlobalSettingsManagerException(String message) {
            super(message);
        }

        GlobalSettingsManagerException(String message, Throwable throwable) {
            super(message, throwable);
        }
    }
}
