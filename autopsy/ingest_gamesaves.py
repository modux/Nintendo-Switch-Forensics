#!/usr/bin/python
# -*- coding: utf-8 -*-

# Simple Nintendo Switch gamesaves ingest module for Autopsy.

import os
import json
import inspect
import binascii
from jarray import zeros
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


class GamesaveIngestModuleFactory(IngestModuleFactoryAdapter):
    moduleName = "Nintendo Switch - Game Saves"

    def getModuleDisplayName(self):
        return self.moduleName

    def getModuleDescription(self):
        return "Module that pulls out gamesaves from a Nintendo Switch. (USER partition)"

    def getModuleVersionNumber(self):
        return "0.1"

    def isFileIngestModuleFactory(self):
        return True

    def createFileIngestModule(self, ingestOptions):
        return GamesaveIngestModule()


class GamesaveIngestModule(FileIngestModule):

    _logger = Logger.getLogger(GamesaveIngestModuleFactory.moduleName)

    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)

    def startUp(self, context):
        self.filesFound = 0

        skCase = Case.getCurrentCase().getSleuthkitCase();
        # Create the artifact type, if it exists then catch the error
        try:
            self.log(Level.INFO, "Begin Create New Artifact")
            artID_ns_gs = skCase.addArtifactType("TSK_ART_NS_GS", "Nintendo Switch - Game Saves")
        except:
            self.log(Level.INFO, "Artifact Creation Error: NS - Game Saves")

        # Create the attribute type, if it exists then catch the error
        try:
            attID_ns_gid = skCase.addArtifactAttributeType('TSK_ATT_NS_GAME', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Game")
        except:
            self.log(Level.INFO, "Attribute Creation Error: NS Game")

        try:
            attID_ns_ts = skCase.addArtifactAttributeType('TSK_ATT_NS_TS', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Last Saved")
        except:
            self.log(Level.INFO, "Attribute Creation Error: NS TS")

        try:
            attID_ns_info = skCase.addArtifactAttributeType('TSK_ATT_NS_INFO', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Game Information")
        except:
            self.log(Level.INFO, "Attribute Creation Error: NS INFO")

        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'game_ids.json')

        if not os.path.exists(path):
            raise IngestModuleException("game_ids was not found in module folder")

        with open(path, "r") as data_file:
            self.gids = json.load(data_file)

        pass

    def process(self, file):

        skCase = Case.getCurrentCase().getSleuthkitCase()

        artID_ns_gs_id = skCase.getArtifactTypeID("TSK_ART_NS_GS")
        artID_ns_gs = skCase.getArtifactType("TSK_ART_NS_GS")

        attID_ns_gid = skCase.getAttributeType("TSK_ATT_NS_GAME")
        attID_ns_ts = skCase.getAttributeType("TSK_ATT_NS_TS")
        attID_ns_info = skCase.getAttributeType("TSK_ATT_NS_INFO")

        # Skip non-files
        if ((file.getType() == TskData.TSK_DB_FILES_TYPE_ENUM.UNALLOC_BLOCKS) or (file.getType() == TskData.TSK_DB_FILES_TYPE_ENUM.UNUSED_BLOCKS) or (file.isFile() is False)):
            return IngestModule.ProcessResult.OK

        self.log(Level.INFO, "Found a Bootup timestamp: " + file.getParentPath())

        # Currently searches through all save files, regardless of which partition is used. Currently runs very quickly so does not need to be optimised at this point.
        if file.getParentPath().upper() == "/SAVE/":

            self.log(Level.INFO, "Found a game save: " + file.getName())
            self.filesFound += 1

            buf = zeros(8, 'b')
            file.read(buf, 1752, 8)

            b_gid = binascii.hexlify(buf)

            str_gid = "".join(reversed([b_gid[i:i + 2] for i in range(0, len(b_gid), 2)])).upper()

            if str_gid in self.gids:

                timestamp = file.getMtimeAsDate()
                game = self.gids[str_gid]
                more_info = "https://ec.nintendo.com/apps/%s/GB" % str_gid

                # Don't add to blackboard if the artifact already exists
                artifactList = file.getArtifacts(artID_ns_gs_id)
                for artifact in artifactList:
                    dupe_test = artifact.getAttribute(attID_ns_gid)
                    if dupe_test:
                        return IngestModule.ProcessResult.OK

                art = file.newArtifact(artID_ns_gs_id)

                art.addAttribute(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_SET_NAME.getTypeID(), GamesaveIngestModuleFactory.moduleName, "Nintendo Switch - Game Save"))
                art.addAttribute(BlackboardAttribute(attID_ns_gid, GamesaveIngestModuleFactory.moduleName, game))
                art.addAttribute(BlackboardAttribute(attID_ns_ts, GamesaveIngestModuleFactory.moduleName, timestamp))
                art.addAttribute(BlackboardAttribute(attID_ns_info, GamesaveIngestModuleFactory.moduleName, more_info))

                IngestServices.getInstance().fireModuleDataEvent(ModuleDataEvent(GamesaveIngestModuleFactory.moduleName, artID_ns_gs, None))

            return IngestModule.ProcessResult.OK

    def shutDown(self):
        message = IngestMessage.createMessage(
            IngestMessage.MessageType.DATA, GamesaveIngestModuleFactory.moduleName, str(self.filesFound) + " game saves found")
        _ = IngestServices.getInstance().postMessage(message)
