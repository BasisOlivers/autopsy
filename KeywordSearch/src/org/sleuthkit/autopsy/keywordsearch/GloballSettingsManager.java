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

class GlobalSettingsManager {

    private static GlobalSettingsManager currInstance;
    private KeywordSearchGlobalSettings settings;

    private GlobalSettingsManager() {
        try {
            try (NbObjectInputStream in = new NbObjectInputStream(new FileInputStream(DB_SERIALIZATION_FILE_PATH))) {
                HashDbSerializationSettings filesSetsSettings = (HashDbSerializationSettings) in.readObject();
                this.setFields(filesSetsSettings);
                return true;
            }
        } catch (IOException | ClassNotFoundException ex) {
            throw new PersistenceException(String.format("Failed to read settings from %s", DB_SERIALIZATION_FILE_PATH), ex);
        }
    }

    static synchronized GlobalSettingsManager getInstance() {
        if (currInstance == null) {
            currInstance = new GlobalSettingsManager();
        }
        return currInstance;
    }
}
