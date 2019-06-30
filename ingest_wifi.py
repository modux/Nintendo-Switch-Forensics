#!/usr/bin/python
# -*- coding: utf-8 -*-

# Nintendo Switch Wi-Fi Details Autopsy Module

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


class WiFiIngestModuleFactory(IngestModuleFactoryAdapter):

    moduleName = "Nintendo Switch - Wi-Fi"

    def getModuleDisplayName(self):
        return self.moduleName

    def getModuleDescription(self):
        return "Module that discovers Wi-Fi SSIDs and associated PSKs from Nintendo Switches."

    def getModuleVersionNumber(self):
        return "1.0"

    # Return true if module wants to get called for each file
    def isFileIngestModuleFactory(self):
        return True

    # can return null if isFileIngestModuleFactory returns false
    def createFileIngestModule(self, ingestOptions):
        return WiFiIngestModule()


class WiFiIngestModule(FileIngestModule):

    _logger = Logger.getLogger(WiFiIngestModuleFactory.moduleName)
    ARTIFACTTYPENAME_NS_WIFI = "TSK_ART_NS_WIFI"

    NS_WIFI_ATTRIBUTES = {
        "SSID": ["TSK_ATT_NS_WIFI_SSID", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "SSID"],
        "PSK": ["TSK_ATT_NS_WIFI_PSK", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "PSK"],
    }

    # http://sleuthkit.org/sleuthkit/docs/jni-docs/4.3/mod_bbpage.html

    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)

    def startUp(self, context):
        self.filesFound = 0

        skCase = Case.getCurrentCase().getSleuthkitCase()

        # Create the artifact type, if it exists then catch the error
        try:
            self.log(Level.INFO, "Begin Create New Artifact")
            artID_ns_ss = skCase.addArtifactType(self.ARTIFACTTYPENAME_NS_WIFI, "Nintendo Switch - Wireless Credentials")
        except:
            self.log(Level.INFO, "Artifact Creation Error: NS - Wi-Fi")
            artID_ns_ss = skCase.getArtifactType(self.ARTIFACTTYPENAME_NS_WIFI)

        for attribute in self.NS_WIFI_ATTRIBUTES.keys():
            # Create the attribute type, if it exists then catch the error
            try:
                attID_ns_gid = skCase.addArtifactAttributeType(
                    self.NS_WIFI_ATTRIBUTES[attribute][0],
                    self.NS_WIFI_ATTRIBUTES[attribute][1],
                    self.NS_WIFI_ATTRIBUTES[attribute][2]
                )
            except:
                self.log(Level.INFO, "Attribute Creation Error: %s" % (self.NS_WIFI_ATTRIBUTES[attribute][0]))

            self.NS_WIFI_ATTRIBUTES[attribute].append(skCase.getAttributeType(self.NS_WIFI_ATTRIBUTES[attribute][0]))

        pass

    # Where the analysis is done.  Each file will be passed into here.
    # The 'file' object being passed in is of type org.sleuthkit.datamodel.AbstractFile.
    # See: http://www.sleuthkit.org/sleuthkit/docs/jni-docs/classorg_1_1sleuthkit_1_1datamodel_1_1_abstract_file.html
    # TODO: Add your analysis code in here.
    def process(self, file):
        skCase = Case.getCurrentCase().getSleuthkitCase()
        ARTID_NS_WIFI = skCase.getArtifactTypeID(self.ARTIFACTTYPENAME_NS_WIFI)

        networks = {}

        skCase = Case.getCurrentCase().getSleuthkitCase()

        # Skip non-files
        if ((file.getType() == TskData.TSK_DB_FILES_TYPE_ENUM.UNALLOC_BLOCKS)
                or (file.getType() == TskData.TSK_DB_FILES_TYPE_ENUM.UNUSED_BLOCKS)
                or (file.isFile() is False)):
            return IngestModule.ProcessResult.OK

        blackboard = Case.getCurrentCase().getServices().getBlackboard()

        if (file.getName().lower() == "8000000000000050"):
            artifactList = file.getArtifacts(ARTID_NS_WIFI)

            self.log(Level.INFO, "Found the file" + file.getName())
            self.filesFound += 1

            inputStream = ReadContentInputStream(file)
            buffer = jarray.zeros(8192, "b")
            totLen = 0
            lengthofbuffer = inputStream.read(buffer)
            while lengthofbuffer != -1:
                totLen = totLen + lengthofbuffer
                lengthofbuffer = inputStream.read(buffer)
                currentBuffer = buffer.tostring()
                regex = "\x00[^\x00]{16}\x03(?:[^\x20-\x7f]+)(?P<ssid>[\x20-\x7f]+?)\x00(?:[^\x20-\x7f]+)(?P<pass>[\x20-\x7f]+?)\x00"
                x = re.finditer(regex, currentBuffer)
                for network in x:
                    networks[network.group('ssid')] = network.group('pass')

            for ssid, psk in networks.items():
                self.log(Level.INFO, ssid)
                # Don't add to blackboard if the artifact already exists
                for artifact in artifactList:
                    artifactSSID = artifact.getAttribute(self.NS_WIFI_ATTRIBUTES["SSID"][3])
                    if artifactSSID.getValueString() == ssid:
                        pass

                art = file.newArtifact(ARTID_NS_WIFI)
                art.addAttribute(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_SET_NAME.getTypeID(), WiFiIngestModuleFactory.moduleName, "Nintendo Switch - Wireless Credentials"))
                art.addAttribute(BlackboardAttribute(self.NS_WIFI_ATTRIBUTES["SSID"][3], WiFiIngestModuleFactory.moduleName, ssid))
                art.addAttribute(BlackboardAttribute(self.NS_WIFI_ATTRIBUTES["PSK"][3], WiFiIngestModuleFactory.moduleName, psk))

                try:
                    # index the artifact for keyword search
                    blackboard.indexArtifact(art)
                except Blackboard.BlackboardException:
                    self.log(Level.SEVERE, "Error indexing artifact " + art.getDisplayName())

                IngestServices.getInstance().fireModuleDataEvent(ModuleDataEvent(WiFiIngestModuleFactory.moduleName, skCase.getArtifactType(self.ARTIFACTTYPENAME_NS_WIFI), None))

            return IngestModule.ProcessResult.OK

    def shutDown(self):
        message = IngestMessage.createMessage(
            IngestMessage.MessageType.DATA, WiFiIngestModuleFactory.moduleName,
            str(self.filesFound) + " files found")
        _ = IngestServices.getInstance().postMessage(message)
