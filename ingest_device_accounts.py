#!/usr/bin/python
# -*- coding: utf-8 -*-

# Nintendo Switch Device Accounts Autopsy Module

import jarray
import inspect
import re
import json
from java.util.logging import Level
from org.sleuthkit.datamodel import ReadContentInputStream
from org.sleuthkit.datamodel import BlackboardArtifact
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


class DeviceAccountIngestModuleFactory(IngestModuleFactoryAdapter):
    moduleName = "Nintendo Switch - Device User Accounts"

    def getModuleDisplayName(self):
        return self.moduleName

    def getModuleDescription(self):
        return "Module to extract all user accounts from the device."

    def getModuleVersionNumber(self):
        return "1.0"

    # Return true if module wants to get called for each file
    def isFileIngestModuleFactory(self):
        return True

    # can return null if isFileIngestModuleFactory returns false
    def createFileIngestModule(self, ingestOptions):
        return DeviceAccountIngestModule()


class DeviceAccountIngestModule(FileIngestModule):
    _logger = Logger.getLogger(DeviceAccountIngestModuleFactory.moduleName)
    ARTIFACTTYPENAME_NS_DEVICE_ACCOUNT = "TSK_ART_NS_DEVICE_ACCOUNT"

    NS_ACCOUNT_ATTRIBUTES = {
        "gender": ["TSK_ATT_NS_ACCOUNT_GENDER", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Gender"],
        "timezone": ["TSK_ATT_NS_ACCOUNT_TIMEZONE", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Timezone"],
        "email": ["TSK_ATT_NS_ACCOUNT_EMAIL", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Email"],
        "nickname": ["TSK_ATT_NS_ACCOUNT_NICKNAME", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Nickname"],
        "isChild": ["TSK_ATT_NS_ACCOUNT_ISCHILD", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "isChild"],
        "language": ["TSK_ATT_NS_ACCOUNT_LANGUAGE", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Language"],
        "birthday": ["TSK_ATT_NS_ACCOUNT_BIRTHDAY", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Birthday"],
        "country": ["TSK_ATT_NS_ACCOUNT_COUNTRY", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Country"],
        "isNnLinked": ["TSK_ATT_NS_ACCOUNT_ISNNLINKED", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Linked Nintendo Account"],
        "isTwitterLinked": ["TSK_ATT_NS_ACCOUNT_ISTWITTERLINKED", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Linked Twitter Account"],
        "isFacebookLinked": ["TSK_ATT_NS_ACCOUNT_ISFACEBOOKLINKED", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Linked Facebook Account"],
        "isGoogleLinked": ["TSK_ATT_NS_ACCOUNT_ISGOOGLELINKED", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Linked Google Account"]
    }

    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)

    def startUp(self, context):
        self.filesFound = 0

        skCase = Case.getCurrentCase().getSleuthkitCase()

        # Create the artifact type, if it exists then catch the error
        try:
            self.log(Level.INFO, "Begin Create New Artifact")
            _ = skCase.addArtifactType(self.ARTIFACTTYPENAME_NS_DEVICE_ACCOUNT, "Nintendo Switch - Device Account")
        except:
            self.log(Level.WARNING, "Artifact Creation Error: NS - Device Account")
            _ = skCase.getArtifactType(self.ARTIFACTTYPENAME_NS_DEVICE_ACCOUNT)

        for attribute in self.NS_ACCOUNT_ATTRIBUTES.keys():
            # Create the attribute type, if it exists then catch the error
            try:
                _ = skCase.addArtifactAttributeType(
                    self.NS_ACCOUNT_ATTRIBUTES[attribute][0],
                    self.NS_ACCOUNT_ATTRIBUTES[attribute][1],
                    self.NS_ACCOUNT_ATTRIBUTES[attribute][2]
                )
            except:
                self.log(Level.WARNING, "Attribute Creation Error: %s" % (self.NS_ACCOUNT_ATTRIBUTES[attribute][0]))

            self.NS_ACCOUNT_ATTRIBUTES[attribute].append(skCase.getAttributeType(self.NS_ACCOUNT_ATTRIBUTES[attribute][0]))

        pass

    def process(self, file):
        skCase = Case.getCurrentCase().getSleuthkitCase()
        ARTID_NS_DEVICE_ACCOUNT_ID = skCase.getArtifactTypeID(self.ARTIFACTTYPENAME_NS_DEVICE_ACCOUNT)

        # Skip non-files
        if ((file.getType() == TskData.TSK_DB_FILES_TYPE_ENUM.UNALLOC_BLOCKS) or (file.getType() == TskData.TSK_DB_FILES_TYPE_ENUM.UNUSED_BLOCKS) or not (file.isFile())):
            return IngestModule.ProcessResult.OK

        # Use blackboard class to index blackboard artifacts for keyword search
        # blackboard = Case.getCurrentCase().getServices().getBlackboard()

        if file.getName() == "8000000000000010":
            self.filesFound += 1

            artifactList = file.getArtifacts(BlackboardArtifact.ARTIFACT_TYPE.TSK_OS_ACCOUNT)
            self.log(Level.INFO, str(artifactList.size()))

            users = self.getUsersFromFile(file)

            artifactList = file.getArtifacts(ARTID_NS_DEVICE_ACCOUNT_ID)
            for user in users:
                # Don't add to blackboard if the artifact already exists
                for artifact in artifactList:
                    artifactNickname = artifact.getAttribute(self.NS_ACCOUNT_ATTRIBUTES["nickname"][3])
                    artifactEmail = artifact.getAttribute(self.NS_ACCOUNT_ATTRIBUTES["email"][3])
                    if artifactNickname and artifactEmail:
                        if artifactNickname.getValueString() == user["nickname"]:
                            if artifactEmail.getValueString() == user["email"]:
                                return IngestModule.ProcessResult.OK

                art = file.newArtifact(ARTID_NS_DEVICE_ACCOUNT_ID)

                art.addAttribute(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_SET_NAME.getTypeID(), DeviceAccountIngestModuleFactory.moduleName, "Nintendo Switch - Device Accounts"))

                for attribute in self.NS_ACCOUNT_ATTRIBUTES.keys():
                    art.addAttribute(BlackboardAttribute(self.NS_ACCOUNT_ATTRIBUTES[attribute][3], DeviceAccountIngestModuleFactory.moduleName, str(user[attribute])))

                # Fire an event to notify the UI and others that there is a new artifact
                IngestServices.getInstance().fireModuleDataEvent(ModuleDataEvent(DeviceAccountIngestModuleFactory.moduleName, skCase.getArtifactType(self.ARTIFACTTYPENAME_NS_DEVICE_ACCOUNT), None))

        return IngestModule.ProcessResult.OK

    def getUsersFromFile(self, file):
        inputStream = ReadContentInputStream(file)
        users = []
        buffer = jarray.zeros(1024, "b")
        totLen = 0
        len = inputStream.read(buffer)
        while len != -1:
            totLen = totLen + len
            len = inputStream.read(buffer)
            currentBuffer = buffer.tostring()
            x = re.search("^\{.*\"gender\".*\}", currentBuffer)
            if x:
                result = x.string.replace("\x00", "")
                d = json.loads(result)
                users.append(d)

        return users

    # Where any shutdown code is run and resources are freed.
    # TODO: Add any shutdown code that you need here.
    def shutDown(self):
        # As a final part of this example, we'll send a message to the ingest inbox with the number of files found (in this thread)
        message = IngestMessage.createMessage(
            IngestMessage.MessageType.DATA, DeviceAccountIngestModuleFactory.moduleName,
            str(self.filesFound) + " files found")
        _ = IngestServices.getInstance().postMessage(message)
