#!/usr/bin/python
# -*- coding: utf-8 -*-

# Simple Nintendo Switch screenshot ingest module for Autopsy.

import os
import re
import json
import inspect
from datetime import datetime
from java.util.logging import Level
from org.sleuthkit.datamodel import BlackboardAttribute
from org.sleuthkit.datamodel import TskData
from org.sleuthkit.autopsy.ingest import IngestModule
from org.sleuthkit.autopsy.ingest.IngestModule import IngestModuleException
from org.sleuthkit.autopsy.ingest import FileIngestModule
from org.sleuthkit.autopsy.ingest import IngestModuleFactoryAdapter
from org.sleuthkit.autopsy.ingest import IngestMessage
from org.sleuthkit.autopsy.ingest import IngestServices
from org.sleuthkit.autopsy.ingest import ModuleDataEvent
from org.sleuthkit.autopsy.coreutils import Logger
from org.sleuthkit.autopsy.casemodule import Case


class FindScreenshotsIngestModuleFactory(IngestModuleFactoryAdapter):
    moduleName = "Nintendo Switch - Screenshot Finder"

    def getModuleDisplayName(self):
        return self.moduleName

    # TODO: Give it a description
    def getModuleDescription(self):
        return "Module that pulls out Nintendo Switch screenshots and adds them to the timeline."

    def getModuleVersionNumber(self):
        return "1.0"

    # Return true if module wants to get called for each file
    def isFileIngestModuleFactory(self):
        return True

    # can return null if isFileIngestModuleFactory returns false
    def createFileIngestModule(self, ingestOptions):
        return FindScreenshotsIngestModule()


class FindScreenshotsIngestModule(FileIngestModule):

    _logger = Logger.getLogger(FindScreenshotsIngestModuleFactory.moduleName)

    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)

    def startUp(self, context):
        self.filesFound = 0

        skCase = Case.getCurrentCase().getSleuthkitCase()

        # Create the artifact type, if it exists then catch the error
        try:
            self.log(Level.INFO, "Begin Create New Artifact")
            artID_ns_ss = skCase.addArtifactType("TSK_ART_NS_SCREENSHOTS", "Nintendo Switch - Screenshots")
        except:
            self.log(Level.INFO, "Artifact Creation Error: NS - Screenshots")

        # Create the attribute type, if it exists then catch the error
        try:
            attID_ns_gid = skCase.addArtifactAttributeType('TSK_ATT_NS_GAME', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Game")
        except:
            self.log(Level.INFO, "Attribute Creation Error: NS Game")

        try:
            attID_ns_ts = skCase.addArtifactAttributeType('TSK_ATT_NS_TIMESTAMP', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Taken On")
        except:
            self.log(Level.INFO, "Attribute Creation Error: NS Timestamp")

        pass

    def process(self, file):

        skCase = Case.getCurrentCase().getSleuthkitCase()

        artID_ns_ss = skCase.getArtifactType("TSK_ART_NS_SCREENSHOTS")

        artID_ns_ss_id = skCase.getArtifactTypeID("TSK_ART_NS_SCREENSHOTS")

        attID_ns_gid = skCase.getAttributeType("TSK_ATT_NS_GAME")
        attID_ns_ts = skCase.getAttributeType("TSK_ATT_NS_TIMESTAMP")

        # Skip non-files
        if ((file.getType() == TskData.TSK_DB_FILES_TYPE_ENUM.UNALLOC_BLOCKS) or (file.getType() == TskData.TSK_DB_FILES_TYPE_ENUM.UNUSED_BLOCKS) or (file.isFile() is False)):
            return IngestModule.ProcessResult.OK

        # Flag files with .jpg in the name and make a blackboard artifact.
        if file.getName().lower().endswith(".jpg") or file.getName().lower().endswith(".mp4") or file.getName().lower().endswith(".png"):

            if re.match(r"[0-9]{16}-[0-9a-fA-F]{32}\.(jpg|png|mp4)", file.getName()):

                self.log(Level.INFO, "Found a Switch screenshot: " + file.getName())
                self.filesFound += 1

                self.path_to_data = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'game_hash_ids.json')

                if not os.path.exists(self.path_to_data):
                    raise IngestModuleException("game_ids was not found in module folder")

                filename = file.getName().upper()
                timestamp = filename.split("-")[0]
                parsed_ts = datetime.strptime(timestamp, "%Y%m%d%H%M%S%f").strftime('%H:%M %d/%m/%Y')
                gameID = filename.split("-")[1].split(".")[0]

                with open(self.path_to_data, "r") as data_file:
                    gids = json.load(data_file)

                if gameID in gids:
                    game = gids[gameID]
                else:
                    game = "Unknown gameID"

                # Don't add to blackboard if the artifact already exists
                artifactList = file.getArtifacts(artID_ns_ss_id)
                for artifact in artifactList:
                    dupe_test = artifact.getAttribute(attID_ns_gid)
                    if dupe_test:
                        return IngestModule.ProcessResult.OK

                art = file.newArtifact(artID_ns_ss_id)

                art.addAttribute(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_SET_NAME.getTypeID(), FindScreenshotsIngestModuleFactory.moduleName, "Nintendo Switch - Screenshots"))
                art.addAttribute(BlackboardAttribute(attID_ns_gid, FindScreenshotsIngestModuleFactory.moduleName, game))
                art.addAttribute(BlackboardAttribute(attID_ns_ts, FindScreenshotsIngestModuleFactory.moduleName, parsed_ts))

                # Fire an event to notify the UI and others that there is a new artifact
                IngestServices.getInstance().fireModuleDataEvent(ModuleDataEvent(FindScreenshotsIngestModuleFactory.moduleName, artID_ns_ss, None))

        return IngestModule.ProcessResult.OK

    def shutDown(self):
        message = IngestMessage.createMessage(
            IngestMessage.MessageType.DATA, FindScreenshotsIngestModuleFactory.moduleName, str(self.filesFound) + " files found")
        _ = IngestServices.getInstance().postMessage(message)
