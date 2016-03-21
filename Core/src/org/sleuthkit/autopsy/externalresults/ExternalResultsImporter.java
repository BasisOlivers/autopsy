/*
 * Autopsy Forensic Browser
 *
 * Copyright 2014 Basis Technology Corp.
 * Contact: carrier <at> sleuthkit <dot> org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this localFile except in compliance with the License.
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
package org.sleuthkit.autopsy.externalresults;

import java.io.File;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.logging.Level;
import org.openide.util.Exceptions;
import org.openide.util.NbBundle;
import org.sleuthkit.autopsy.casemodule.Case;
import org.sleuthkit.autopsy.casemodule.services.Blackboard;
import org.sleuthkit.autopsy.casemodule.services.FileManager;
import org.sleuthkit.autopsy.coreutils.ErrorInfo;
import org.sleuthkit.autopsy.coreutils.Logger;
import org.sleuthkit.autopsy.coreutils.MessageNotifyUtil;
import org.sleuthkit.autopsy.ingest.IngestModule;
import org.sleuthkit.autopsy.ingest.IngestServices;
import org.sleuthkit.autopsy.ingest.ModuleContentEvent;
import org.sleuthkit.autopsy.ingest.ModuleDataEvent;
import org.sleuthkit.datamodel.AbstractFile;
import org.sleuthkit.datamodel.BlackboardArtifact;
import org.sleuthkit.datamodel.BlackboardAttribute;
import org.sleuthkit.datamodel.Content;
import org.sleuthkit.datamodel.DerivedFile;
import org.sleuthkit.datamodel.SleuthkitCase;
import org.sleuthkit.datamodel.TskCoreException;
import org.sleuthkit.datamodel.TskDataException;

/**
 * Uses a standard representation of results data (e.g., artifacts, derived
 * files, reports) to import results generated by a process external to Autopsy
 * into Autopsy.
 */
public final class ExternalResultsImporter {

    private static final Logger logger = Logger.getLogger(ExternalResultsImporter.class.getName());
    private static final HashSet<Integer> standardArtifactTypeIds = new HashSet<>();
    private final List<ErrorInfo> errors = new ArrayList<>();
    private Blackboard blackboard;

    static {
        for (BlackboardArtifact.ARTIFACT_TYPE artifactType : BlackboardArtifact.ARTIFACT_TYPE.values()) {
            standardArtifactTypeIds.add(artifactType.getTypeID());
        }
    }

    /**
     * Import results generated by a process external to Autopsy into Autopsy.
     *
     * @param results A standard representation of results data (e.g.,
     * artifacts, derived files, reports)from the data source.
     *
     * @return A collection of error messages, possibly empty. The error
     * messages are already logged but are provided to allow the caller to
     * provide additional user feedback via the Autopsy user interface.
     */
    public List<ErrorInfo> importResults(ExternalResults results) {
        blackboard = Case.getCurrentCase().getServices().getBlackboard();
        // Import files first, they may be artifactData sources.
        importDerivedFiles(results);
        importArtifacts(results);
        importReports(results);
        List<ErrorInfo> importErrors = new ArrayList<>(this.errors);
        this.errors.clear();
        return importErrors;
    }

    private void importDerivedFiles(ExternalResults results) {
        FileManager fileManager = Case.getCurrentCase().getServices().getFileManager();
        for (ExternalResults.DerivedFile fileData : results.getDerivedFiles()) {
            String localPath = fileData.getLocalPath();
            try {
                File localFile = new File(localPath);
                if (localFile.exists()) {
                    String relativePath = this.getPathRelativeToCaseFolder(localPath);
                    if (!relativePath.isEmpty()) {
                        String parentFilePath = fileData.getParentPath();
                        AbstractFile parentFile = findFileInCaseDatabase(parentFilePath);
                        if (parentFile != null) {
                            DerivedFile derivedFile = fileManager.addDerivedFile(localFile.getName(), relativePath, localFile.length(),
                                    0, 0, 0, 0, // Do not currently have file times for derived files from external processes.
                                    true, parentFile,
                                    "", "", "", ""); // Not currently providing derivation info for derived files from external processes.
                            IngestServices.getInstance().fireModuleContentEvent(new ModuleContentEvent(derivedFile));
                        } else {
                            String errorMessage = NbBundle.getMessage(this.getClass(),
                                    "ExternalResultsImporter.importDerivedFiles.errMsg1.text",
                                    localPath, parentFilePath);
                            ExternalResultsImporter.logger.log(Level.SEVERE, errorMessage);
                            this.errors.add(new ErrorInfo(ExternalResultsImporter.class.getName(), errorMessage));
                        }
                    }
                } else {
                    String errorMessage = NbBundle.getMessage(this.getClass(),
                            "ExternalResultsImporter.importDerivedFiles.errMsg2.text",
                            localPath);
                    ExternalResultsImporter.logger.log(Level.SEVERE, errorMessage);
                    this.errors.add(new ErrorInfo(ExternalResultsImporter.class.getName(), errorMessage));
                }
            } catch (TskCoreException ex) {
                String errorMessage = NbBundle.getMessage(this.getClass(),
                        "ExternalResultsImporter.importDerivedFiles.errMsg3.text",
                        localPath);
                ExternalResultsImporter.logger.log(Level.SEVERE, errorMessage, ex);
                this.errors.add(new ErrorInfo(ExternalResultsImporter.class.getName(), errorMessage, ex));
            }
        }
    }

    private void importArtifacts(ExternalResults results) {
        SleuthkitCase caseDb = Case.getCurrentCase().getSleuthkitCase();
        for (ExternalResults.Artifact artifactData : results.getArtifacts()) {
            try {
                // Add the artifact to the case database.
                int artifactTypeId = caseDb.getArtifactType(artifactData.getType()).getTypeID();
                if (artifactTypeId == -1) {
                    artifactTypeId = caseDb.addBlackboardArtifactType(artifactData.getType(), artifactData.getType()).getTypeID();
                }
                Content sourceFile = findFileInCaseDatabase(artifactData.getSourceFilePath());
                if (sourceFile != null) {
                    BlackboardArtifact artifact = sourceFile.newArtifact(artifactTypeId);

                    // Add the artifact's attributes to the case database.
                    Collection<BlackboardAttribute> attributes = new ArrayList<>();
                    for (ExternalResults.ArtifactAttribute attributeData : artifactData.getAttributes()) {
                        BlackboardAttribute.Type attributeType = caseDb.getAttributeType(attributeData.getType());
                        if (attributeType == null) {
                            switch (attributeData.getValueType()) {
                            case "text": //NON-NLS
                                attributeType = caseDb.addArtifactAttributeType(attributeData.getType(), BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.fromLabel("String"), attributeData.getType()); //NON-NLS
                                break;
                            case "int32": //NON-NLS
                                attributeType = caseDb.addArtifactAttributeType(attributeData.getType(), BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.fromLabel("Integer"), attributeData.getType()); //NON-NLS
                                break;
                            case "int64": //NON-NLS
                                attributeType = caseDb.addArtifactAttributeType(attributeData.getType(), BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.fromLabel("Long"), attributeData.getType()); //NON-NLS
                                break;
                            case "double": //NON-NLS
                                attributeType = caseDb.addArtifactAttributeType(attributeData.getType(), BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.fromLabel("Double"), attributeData.getType()); //NON-NLS
                                break;
                            case "datetime": //NON-NLS
                                attributeType = caseDb.addArtifactAttributeType(attributeData.getType(), BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.fromLabel("DateTime"), attributeData.getType()); //NON-NLS
                            }
                        }

                        switch (attributeData.getValueType()) {
                            case "text": //NON-NLS
                                attributes.add(new BlackboardAttribute(attributeType, attributeData.getSourceModule(), attributeData.getValue()));
                                break;
                            case "int32": //NON-NLS
                                int intValue = Integer.parseInt(attributeData.getValue());
                                attributes.add(new BlackboardAttribute(attributeType, attributeData.getSourceModule(), intValue));
                                break;
                            case "int64": //NON-NLS
                                long longValue = Long.parseLong(attributeData.getValue());
                                attributes.add(new BlackboardAttribute(attributeType, attributeData.getSourceModule(), longValue));
                                break;
                            case "double": //NON-NLS
                                double doubleValue = Double.parseDouble(attributeData.getValue());
                                attributes.add(new BlackboardAttribute(attributeType, attributeData.getSourceModule(), doubleValue));
                                break;
                            case "datetime": //NON-NLS
                                long dateTimeValue = Long.parseLong(attributeData.getValue());
                                attributes.add(new BlackboardAttribute(attributeType, attributeData.getSourceModule(), dateTimeValue));
                                break;
                            default:
                                String errorMessage = NbBundle.getMessage(this.getClass(),
                                        "ExternalResultsImporter.importArtifacts.caseErrMsg1.text",
                                        attributeData.getType(), attributeData.getValue(),
                                        artifactData.getType(), artifactData.getSourceFilePath(),
                                        attributeData.getValueType());
                                ExternalResultsImporter.logger.log(Level.SEVERE, errorMessage);
                                this.errors.add(new ErrorInfo(ExternalResultsImporter.class.getName(), errorMessage));
                                break;
                        }
                    }
                    artifact.addAttributes(attributes);

                    try {
                        // index the artifact for keyword search
                        blackboard.indexArtifact(artifact);
                    } catch (Blackboard.BlackboardException ex) {
                        logger.log(Level.SEVERE, NbBundle.getMessage(Blackboard.class, "Blackboard.unableToIndexArtifact.error.msg", artifact.getDisplayName()), ex); //NON-NLS
                        MessageNotifyUtil.Notify.error(
                                NbBundle.getMessage(Blackboard.class, "Blackboard.unableToIndexArtifact.exception.msg"), artifact.getDisplayName());
                    }

                    if (standardArtifactTypeIds.contains(artifactTypeId)) {
                        IngestServices.getInstance().fireModuleDataEvent(new ModuleDataEvent(this.getClass().getSimpleName(), BlackboardArtifact.ARTIFACT_TYPE.fromID(artifactTypeId)));
                    }
                } else {
                    String errorMessage = NbBundle.getMessage(this.getClass(),
                            "ExternalResultsImporter.importArtifacts.errMsg1.text",
                            artifactData.getType(), artifactData.getSourceFilePath());
                    ExternalResultsImporter.logger.log(Level.SEVERE, errorMessage);
                    this.errors.add(new ErrorInfo(ExternalResultsImporter.class.getName(), errorMessage));
                }
            } catch (TskCoreException ex) {
                String errorMessage = NbBundle.getMessage(this.getClass(),
                        "ExternalResultsImporter.importArtifacts.errMsg2.text",
                        artifactData.getType(), artifactData.getSourceFilePath());
                ExternalResultsImporter.logger.log(Level.SEVERE, errorMessage, ex);
                this.errors.add(new ErrorInfo(ExternalResultsImporter.class.getName(), errorMessage, ex));
            } catch (TskDataException ex) {
                String errorMessage = NbBundle.getMessage(this.getClass(),
                        "ExternalResultsImporter.importArtifacts.errMsg2.text",
                        artifactData.getType(), artifactData.getSourceFilePath());
                ExternalResultsImporter.logger.log(Level.SEVERE, errorMessage, ex);
                this.errors.add(new ErrorInfo(ExternalResultsImporter.class.getName(), errorMessage, ex));
            }
        }
    }

    private void importReports(ExternalResults results) {
        for (ExternalResults.Report report : results.getReports()) {
            String reportPath = report.getLocalPath();
            try {
                File reportFile = new File(reportPath);
                if (reportFile.exists()) {
                    Case.getCurrentCase().addReport(reportPath, report.getSourceModuleName(), report.getReportName());
                } else {
                    String errorMessage = NbBundle.getMessage(this.getClass(), "ExternalResultsImporter.importReports.errMsg1.text", reportPath);
                    ExternalResultsImporter.logger.log(Level.SEVERE, errorMessage);
                    this.errors.add(new ErrorInfo(ExternalResultsImporter.class.getName(), errorMessage));
                }
            } catch (TskCoreException ex) {
                String errorMessage = NbBundle.getMessage(this.getClass(), "ExternalResultsImporter.importReports.errMsg2.text", reportPath);
                ExternalResultsImporter.logger.log(Level.SEVERE, errorMessage, ex);
                this.errors.add(new ErrorInfo(ExternalResultsImporter.class.getName(), errorMessage, ex));
            }
        }
    }

    private AbstractFile findFileInCaseDatabase(String filePath) throws TskCoreException {
        AbstractFile file = null;
        // Split the path into the file name and the parent path.
        String fileName = filePath;
        String parentPath = "";
        int charPos = filePath.lastIndexOf("/");
        if (charPos >= 0) {
            fileName = filePath.substring(charPos + 1);
            parentPath = filePath.substring(0, charPos + 1);
        }
        // Find the file.
        String condition = "name='" + fileName + "' AND parent_path='" + parentPath + "'"; //NON-NLS
        List<AbstractFile> files = Case.getCurrentCase().getSleuthkitCase().findAllFilesWhere(condition);
        if (!files.isEmpty()) {
            file = files.get(0);
            if (files.size() > 1) {
                String errorMessage = NbBundle.getMessage(this.getClass(), "ExternalResultsImporter.findFileInCaseDatabase.errMsg1.text", filePath);
                this.recordError(errorMessage);
            }
        }
        return file;
    }

    private String getPathRelativeToCaseFolder(String localPath) {
        String relativePath = "";
        String caseDirectoryPath = Case.getCurrentCase().getCaseDirectory();
        Path path = Paths.get(localPath);
        if (path.isAbsolute()) {
            Path pathBase = Paths.get(caseDirectoryPath);
            try {
                Path pathRelative = pathBase.relativize(path);
                relativePath = pathRelative.toString();
            } catch (IllegalArgumentException ex) {
                String errorMessage = NbBundle.getMessage(this.getClass(),
                        "ExternalResultsImporter.getPathRelativeToCaseFolder.errMsg1.text",
                        localPath, caseDirectoryPath);
                this.recordError(errorMessage, ex);
            }
        } else {
            String errorMessage = NbBundle.getMessage(this.getClass(),
                    "ExternalResultsImporter.getPathRelativeToCaseFolder.errMsg2.text",
                    localPath, caseDirectoryPath);
            this.recordError(errorMessage);
        }
        return relativePath;
    }

//    private static boolean isStandardArtifactType(int artifactTypeId) {        
//        for (BlackboardArtifact.ARTIFACT_TYPE art : BlackboardArtifact.ARTIFACT_TYPE.values()) {
//            if (art.getTypeID() == artifactTypeId) {
//                return true;
//            }
//        }
//        return false;
//    }    
//    
    private void recordError(String errorMessage) {
        ExternalResultsImporter.logger.log(Level.SEVERE, errorMessage);
        this.errors.add(new ErrorInfo(this.getClass().getName(), errorMessage));
    }

    private void recordError(String errorMessage, Exception ex) {
        ExternalResultsImporter.logger.log(Level.SEVERE, errorMessage, ex);
        this.errors.add(new ErrorInfo(this.getClass().getName(), errorMessage));
    }
}
