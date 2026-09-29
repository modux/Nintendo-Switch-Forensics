#!/usr/bin/python
# -*- coding: utf-8 -*-

# Nintendo Switch last boot ingest module for Autopsy

import inspect
from java.util.logging import Level
from org.sleuthkit.datamodel import BlackboardAttribute
from org.sleuthkit.datamodel import TskData
from org.sleuthkit.autopsy.ingest import IngestModule
from org.sleuthkit.autopsy.ingest import FileIngestModule
from org.sleuthkit.autopsy.ingest import IngestModuleFactoryAdapter
from org.sleuthkit.autopsy.ingest import IngestMessage
from org.sleuthkit.autopsy.ingest import IngestServices
from org.sleuthkit.autopsy.ingest import ModuleDataEvent
from org.sleuthkit.autopsy.coreutils import Logger
from org.sleuthkit.autopsy.casemodule import Case


class FindLastBootIngestModuleFactory(IngestModuleFactoryAdapter):
    moduleName = "Nintendo Switch - Last Boot Time"

    def getModuleDisplayName(self):
        return self.moduleName

    def getModuleDescription(self):
        return "Module that pulls out the last boot time for a Nintendo Switch."

    def getModuleVersionNumber(self):
        return "0.2"

    def isFileIngestModuleFactory(self):
        return True

    def createFileIngestModule(self, ingestOptions):
        return FindLastBootIngestModule()


class FindLastBootIngestModule(FileIngestModule):

    _logger = Logger.getLogger(FindLastBootIngestModuleFactory.moduleName)

    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)

    def startUp(self, context):
        self.filesFound = 0

        skCase = Case.getCurrentCase().getSleuthkitCase()

        # Create the artifact type, if it exists then catch the error
        try:
            self.log(Level.INFO, "Begin Create New Artifact")
            artID_ns_lboot = skCase.addArtifactType("TSK_ART_NS_LBOOT", "Nintendo Switch - Last Boot Time")
        except:
            self.log(Level.INFO, "Artifact Creation Error: NS - Last Boot Time")

        # Create the attribute type, if it exists then catch the error
        try:
            attID_ns_lboot = skCase.addArtifactAttributeType('TSK_ATT_NS_LBOOT', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Last Boot")
        except:
            self.log(Level.INFO, "Attribute Creation Error: NS Last Boot")

        pass

    def process(self, file):

        skCase = Case.getCurrentCase().getSleuthkitCase()

        artID_ns_lboot = skCase.getArtifactType("TSK_ART_NS_LBOOT")
        artID_ns_lboot_id = skCase.getArtifactTypeID("TSK_ART_NS_LBOOT")

        attID_ns_lboot = skCase.getAttributeType("TSK_ATT_NS_LBOOT")

        if ((file.getType() == TskData.TSK_DB_FILES_TYPE_ENUM.UNALLOC_BLOCKS)
                or (file.getType() == TskData.TSK_DB_FILES_TYPE_ENUM.UNUSED_BLOCKS)
                or (file.isFile() is False)):
            return IngestModule.ProcessResult.OK

        if file.getName().upper() == "8000000000000060":

            self.log(Level.INFO, "Found a Bootup timestamp: " + file.getName())
            self.filesFound += 1

            timestamp = file.getMtimeAsDate()

            # Lets not add to blackboard if the artifact already exists
            artifactList = file.getArtifacts(artID_ns_lboot_id)
            for artifact in artifactList:
                dupe_test = artifact.getAttribute(attID_ns_lboot)
                if dupe_test:
                    return IngestModule.ProcessResult.OK

            art = file.newArtifact(artID_ns_lboot_id)

            art.addAttribute(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_SET_NAME.getTypeID(), FindLastBootIngestModuleFactory.moduleName, "Nintendo Switch - Last Boot Time"))
            art.addAttribute(BlackboardAttribute(attID_ns_lboot, FindLastBootIngestModuleFactory.moduleName, timestamp))

            # Fire an event to notify the UI and others that there is a new artifact
            IngestServices.getInstance().fireModuleDataEvent(ModuleDataEvent(FindLastBootIngestModuleFactory.moduleName, artID_ns_lboot, None))

        return IngestModule.ProcessResult.OK

    def shutDown(self):
        message = IngestMessage.createMessage(
            IngestMessage.MessageType.DATA, FindLastBootIngestModuleFactory.moduleName, str(self.filesFound) + " boot up records found")
        _ = IngestServices.getInstance().postMessage(message)
