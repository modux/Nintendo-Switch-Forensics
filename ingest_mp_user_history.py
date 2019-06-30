#!/usr/bin/python
# -*- coding: utf-8 -*-

# Simple Nintendo Switch played with user history ingest module for Autopsy.

import os
import json
import shutil
import inspect
import binascii
import tempfile
import subprocess
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


class MpUserHistoryIngestModuleFactory(IngestModuleFactoryAdapter):
    moduleName = "Nintendo Switch - Multiplayer User History"

    def getModuleDisplayName(self):
        return self.moduleName

    def getModuleDescription(self):
        return "Module that pulls out multiplayer user history from a Nintendo Switch."

    def getModuleVersionNumber(self):
        return "0.4"

    # Return true if module wants to get called for each file
    def isFileIngestModuleFactory(self):
        return True

    # can return null if isFileIngestModuleFactory returns false
    def createFileIngestModule(self, ingestOptions):
        return MpUserHistoryIngestModule()


class MpUserHistoryIngestModule(FileIngestModule):

    _logger = Logger.getLogger(MpUserHistoryIngestModuleFactory.moduleName)

    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)

    def startUp(self, context):
        self.filesFound = 0

        skCase = Case.getCurrentCase().getSleuthkitCase()
        # Create the artifact type, if it exists then catch the error
        try:
            self.log(Level.INFO, "Begin Create New Artifact")
            artID_ns_mph = skCase.addArtifactType("TSK_ART_NS_MPH", "Nintendo Switch - Multiplayer User History")
        except:
            self.log(Level.INFO, "Artifact Creation Error: NS - Multiplayer User History")

        try:
            attID_ns_cd_mph_user = skCase.addArtifactAttributeType('TSK_ATT_MPH_USER', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "User")
        except:
            self.log(Level.INFO, "Attribute Creation Error: User")

        try:
            attID_ns_cd_mph_game = skCase.addArtifactAttributeType('TSK_ATT_MPH_GAME', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Game")
        except:
            self.log(Level.INFO, "Attribute Creation Error: Game")

        try:
            attID_ns_cd_mph_ts = skCase.addArtifactAttributeType('TSK_ATT_MPH_TS', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Timestamp")
        except:
            self.log(Level.INFO, "Attribute Creation Error: Timestamp")

        self.tmp_path = os.path.join(tempfile.gettempdir(), "switch_mp_user_history")
        self.hac_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dependencies", "hactoolnet.exe")

        if not os.path.exists(self.tmp_path):
            os.mkdir(self.tmp_path)

        if not os.path.exists(self.hac_path):
            raise IngestModuleException("hactoolnet.exe was not found in module folder")

        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'game_ids.json')

        if not os.path.exists(path):
            raise IngestModuleException("game_ids was not found in module folder")

        with open(path, "r") as data_file:
            self.gids = json.load(data_file)

        pass

    def process(self, file):

        skCase = Case.getCurrentCase().getSleuthkitCase()

        artID_ns_mph = skCase.getArtifactType("TSK_ART_NS_MPH")
        artID_ns_mph_id = skCase.getArtifactTypeID("TSK_ART_NS_MPH")

        attID_ns_cd_mph_user = skCase.getAttributeType("TSK_ATT_MPH_USER")
        attID_ns_cd_mph_game = skCase.getAttributeType("TSK_ATT_MPH_GAME")
        # Not implemented.
        # attID_ns_cd_mph_ts = skCase.getAttributeType("TSK_ATT_MPH_TS")

        # Skip non-files
        if ((file.getType() == TskData.TSK_DB_FILES_TYPE_ENUM.UNALLOC_BLOCKS) or (file.getType() == TskData.TSK_DB_FILES_TYPE_ENUM.UNUSED_BLOCKS) or (file.isFile() is False)):
            return IngestModule.ProcessResult.OK

        if (file.getParentPath().upper() == "/SAVE/") and (file.getName().upper() == "0000000000000001"):

            self.log(Level.INFO, "Found MP user history save")
            self.filesFound += 1

            buf = zeros(file.getSize(), 'b')
            file.read(buf, 0, file.getSize())

            tmp_file_path = os.path.join(self.tmp_path, file.getName())

            with open(tmp_file_path, 'wb+') as tmp_file:
                tmp_file.write(buf)

            hac_cmd = [self.hac_path, "-t", "save", "--outdir", self.tmp_path, tmp_file_path]
            subprocess.call(hac_cmd)

            mp_hist_file = os.path.join(self.tmp_path, "history.bin")

            users = []

            with open(mp_hist_file, "rb") as hist_file:
                while True:
                    chunk = binascii.hexlify(hist_file.read(256))
                    if not chunk:
                        break
                    user = {}
                    user["block_a"] = chunk[:48]
                    user["block_b"] = chunk[48:64]
                    user["block_c"] = chunk[64:80]
                    user["block_d"] = chunk[80:192]
                    user["block_e"] = chunk[192:224]
                    user["block_f"] = chunk[224:-1]
                    user["username"] = binascii.unhexlify(user["block_d"]).split("\x00")[0]
                    user["game_id"] = "".join(reversed([user["block_b"][i:i + 2] for i in range(0, len(user["block_b"]), 2)])).upper()
                    if user["game_id"] in self.gids:
                        user["game"] = self.gids[user["game_id"]]
                    users.append(user)

            # Don't add to blackboard if already exists - TODO improve when timestamp is implemented
            artifactList = file.getArtifacts(artID_ns_mph_id)
            seen_users = []
            for artifact in artifactList:
                seen_users.append(artifact.getAttribute(attID_ns_cd_mph_user).getValueString())
            for u in seen_users:
                self.log(Level.INFO, "Ingest MP User - Online multiplayer user found: %s" % u)

            for user in users:

                # Don't add to blackboard if already exists - TODO improve when timestamp is implemented
                if user["username"] in seen_users:
                    return IngestModule.ProcessResult.OK

                art = file.newArtifact(artID_ns_mph_id)

                art.addAttribute(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_SET_NAME.getTypeID(), MpUserHistoryIngestModuleFactory.moduleName, "Nintendo Switch - MP User History"))
                art.addAttribute(BlackboardAttribute(attID_ns_cd_mph_user, MpUserHistoryIngestModuleFactory.moduleName, user["username"]))
                if "game" in user:
                    art.addAttribute(BlackboardAttribute(attID_ns_cd_mph_game, MpUserHistoryIngestModuleFactory.moduleName, user["game"]))

                # Fire an event to notify the UI and others that there is a new artifact
                IngestServices.getInstance().fireModuleDataEvent(ModuleDataEvent(MpUserHistoryIngestModuleFactory.moduleName, artID_ns_mph, None))

            return IngestModule.ProcessResult.OK

    def shutDown(self):
        message = IngestMessage.createMessage(
            IngestMessage.MessageType.DATA, MpUserHistoryIngestModuleFactory.moduleName, str(self.filesFound) + " users found")
        _ = IngestServices.getInstance().postMessage(message)

        # remove temp dir after use
        if os.path.exists(self.tmp_path):
            shutil.rmtree(self.tmp_path)
