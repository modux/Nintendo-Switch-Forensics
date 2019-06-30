#!/usr/bin/python
# -*- coding: utf-8 -*-

# Nintendo Switch Connected Displays Autopsy Module

import jarray
import inspect
import re
from java.util.logging import Level
from org.sleuthkit.datamodel import ReadContentInputStream
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
from org.sleuthkit.autopsy.casemodule.services import Blackboard


class ConnectedDisplayIngestModuleFactory(IngestModuleFactoryAdapter):

    moduleName = "Nintendo Switch - Connected Displays"

    def getModuleDisplayName(self):
        return self.moduleName

    def getModuleDescription(self):
        return "Module That Discovers Connected TVs or Displays"

    def getModuleVersionNumber(self):
        return "1.0"

    def isFileIngestModuleFactory(self):
        return True

    def createFileIngestModule(self, ingestOptions):
        return ConnectedDisplayIngestModule()


class ConnectedDisplayIngestModule(FileIngestModule):

    _logger = Logger.getLogger(ConnectedDisplayIngestModuleFactory.moduleName)
    ARTIFACTTYPENAME_NS_TV = "TSK_ART_NS_TV"

    NS_DISPLAY_ATTRIBUTES = {
        "Name": ["TSK_ATT_NS_TV", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Name"]
    }

    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)

    def startUp(self, context):
        self.filesFound = 0

        skCase = Case.getCurrentCase().getSleuthkitCase()

        # Create the artifact type, if it exists then catch the error
        try:
            self.log(Level.INFO, "Begin Create New Artifact")
            artID_ns_ss = skCase.addArtifactType(self.ARTIFACTTYPENAME_NS_TV, "Nintendo Switch - Connected Displays")
        except:
            self.log(Level.INFO, "Artifact Creation Error: NS - Connected Displays")
            artID_ns_ss = skCase.getArtifactType(self.ARTIFACTTYPENAME_NS_TV)

        for attribute in self.NS_DISPLAY_ATTRIBUTES.keys():
            # Create the attribute type, if it exists then catch the error
            try:
                attID_ns_gid = skCase.addArtifactAttributeType(
                    self.NS_DISPLAY_ATTRIBUTES[attribute][0],
                    self.NS_DISPLAY_ATTRIBUTES[attribute][1],
                    self.NS_DISPLAY_ATTRIBUTES[attribute][2]
                )
            except:
                self.log(Level.INFO, "Attribute Creation Error: %s" % (self.NS_DISPLAY_ATTRIBUTES[attribute][0]))

            self.NS_DISPLAY_ATTRIBUTES[attribute].append(skCase.getAttributeType(self.NS_DISPLAY_ATTRIBUTES[attribute][0]))

        pass

    def process(self, file):
        skCase = Case.getCurrentCase().getSleuthkitCase()
        ARTID_NS_TV = skCase.getArtifactTypeID(self.ARTIFACTTYPENAME_NS_TV)

        names = []

        skCase = Case.getCurrentCase().getSleuthkitCase()

        # Skip non-files
        if ((file.getType() == TskData.TSK_DB_FILES_TYPE_ENUM.UNALLOC_BLOCKS)
                or (file.getType() == TskData.TSK_DB_FILES_TYPE_ENUM.UNUSED_BLOCKS)
                or (file.isFile() is False)):
            return IngestModule.ProcessResult.OK

        blackboard = Case.getCurrentCase().getServices().getBlackboard()

        if file.getName() == "80000000000000d1":
            artifactList = file.getArtifacts(ARTID_NS_TV)

            self.log(Level.INFO, "Found the file" + file.getName())
            self.filesFound += 1

            inputStream = ReadContentInputStream(file)
            buffer = jarray.zeros(2048, "b")
            totLen = 0
            lengthofbuffer = inputStream.read(buffer)
            while lengthofbuffer != -1:
                totLen = totLen + lengthofbuffer
                lengthofbuffer = inputStream.read(buffer)
                currentBuffer = buffer.tostring()
                names = names + re.findall("EdidBlock.*?\\\\xfc\\\\x00(.*?)\\\\n.*?EdidExtensionBlock", repr(currentBuffer))

            noduplicatesnames = list(set(names))
            for tvname in noduplicatesnames:
                # Don't add to blackboard if the artifact already exists
                for artifact in artifactList:
                    artifactName = artifact.getAttribute(self.NS_DISPLAY_ATTRIBUTES["Name"][3])
                    if artifactName.getValueString() == tvname:
                        return IngestModule.ProcessResult.OK

                art = file.newArtifact(ARTID_NS_TV)
                art.addAttribute(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_SET_NAME.getTypeID(), ConnectedDisplayIngestModuleFactory.moduleName, "Nintendo Switch - Connected TV"))
                for attribute in self.NS_DISPLAY_ATTRIBUTES.keys():
                    art.addAttribute(BlackboardAttribute(self.NS_DISPLAY_ATTRIBUTES[attribute][3], ConnectedDisplayIngestModuleFactory.moduleName, str(tvname)))

                try:
                    # index the artifact for keyword search
                    blackboard.indexArtifact(art)
                except Blackboard.BlackboardException:
                    self.log(Level.SEVERE, "Error indexing artifact " + art.getDisplayName())

                IngestServices.getInstance().fireModuleDataEvent(ModuleDataEvent(ConnectedDisplayIngestModuleFactory.moduleName, skCase.getArtifactType(self.ARTIFACTTYPENAME_NS_TV), None))

        return IngestModule.ProcessResult.OK

    def shutDown(self):
        message = IngestMessage.createMessage(
            IngestMessage.MessageType.DATA, ConnectedDisplayIngestModuleFactory.moduleName,
            str(self.filesFound) + " files found")
        _ = IngestServices.getInstance().postMessage(message)
