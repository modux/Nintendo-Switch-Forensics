# Simple Nintendo Switch recent game history ingest module for Autopsy.

import re
import os
import json
import inspect
import binascii
from jarray import zeros
from java.util.logging import Level
from org.sleuthkit.datamodel import SleuthkitCase
from org.sleuthkit.datamodel import AbstractFile
from org.sleuthkit.datamodel import ReadContentInputStream
from org.sleuthkit.datamodel import BlackboardArtifact
from org.sleuthkit.datamodel import BlackboardAttribute
from org.sleuthkit.datamodel import TskData
from org.sleuthkit.autopsy.ingest import IngestModule
from org.sleuthkit.autopsy.ingest.IngestModule import IngestModuleException
from org.sleuthkit.autopsy.ingest import DataSourceIngestModule
from org.sleuthkit.autopsy.ingest import FileIngestModule
from org.sleuthkit.autopsy.ingest import IngestModuleFactoryAdapter
from org.sleuthkit.autopsy.ingest import IngestMessage
from org.sleuthkit.autopsy.ingest import IngestServices
from org.sleuthkit.autopsy.ingest import ModuleDataEvent
from org.sleuthkit.autopsy.coreutils import Logger
from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.autopsy.casemodule.services import Services
from org.sleuthkit.autopsy.casemodule.services import FileManager


class GameHistoryIngestModuleFactory(IngestModuleFactoryAdapter):
    # Factory that defines the name and details of the module and allows Autopsy
    # to create instances of the modules that will do the anlaysis.

    # Will be shown in module list, logs, etc.
    moduleName = "Nintendo Switch - Recent Game History"

    def getModuleDisplayName(self):
        return self.moduleName

    # TODO: Give it a description
    def getModuleDescription(self):
        return "Module that pulls out recent game history from a Nintendo Switch."

    def getModuleVersionNumber(self):
        return "0.1"

    # Return true if module wants to get called for each file
    def isFileIngestModuleFactory(self):
        return True

    # can return null if isFileIngestModuleFactory returns false
    def createFileIngestModule(self, ingestOptions):
        return GameHistoryIngestModule()


# File-level ingest module.  One gets created per thread.
# TODO: Rename this to something more specific. Could just remove "Factory" from above name.
# Looks at the attributes of the passed in file.
class GameHistoryIngestModule(FileIngestModule):

    _logger = Logger.getLogger(GameHistoryIngestModuleFactory.moduleName)

    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)

    # Where any setup and configuration is done
    # 'context' is an instance of org.sleuthkit.autopsy.ingest.IngestJobContext.
    # See: http://sleuthkit.org/autopsy/docs/api-docs/3.1/classorg_1_1sleuthkit_1_1autopsy_1_1ingest_1_1_ingest_job_context.html
    # TODO: Add any setup code that you need here.
    def startUp(self, context):
        self.filesFound = 0

        skCase = Case.getCurrentCase().getSleuthkitCase();
        # Create the artifact type, if it exists then catch the error
        try:
            self.log(Level.INFO, "Begin Create New Artifact")
            artID_ns_rgh = skCase.addArtifactType("TSK_ART_NS_RGH", "Nintendo Switch - Recent Game History")
        except:
            self.log(Level.INFO, "Artifact Creation Error: RGH - Recent Game History")

        # Create the attribute types, if any exist then catch the error
        try:
            attID_ns_rgh_gid = skCase.addArtifactAttributeType('TSK_ATT_NS_RGH_GAME', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Game")
        except:
            self.log(Level.INFO, "Attribute Creation Error: NS Game")

        try:
            attID_ns_rgh_ts = skCase.addArtifactAttributeType('TSK_ATT_NS_RGS_TS', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Time Stamp")
        except:
            self.log(Level.INFO, "Attribute Creation Error: NS TS")

        try:
            attID_ns_rgh_e = skCase.addArtifactAttributeType('TSK_ATT_NS_RGS_E', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Event")
        except:
            self.log(Level.INFO, "Attribute Creation Error: NS E")

        gid_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'game_ids.json')
        with open(gid_path, "r") as data_file:
            self.gids = json.load(data_file)

        pass

    # Where the analysis is done.  Each file will be passed into here.
    # The 'file' object being passed in is of type org.sleuthkit.datamodel.AbstractFile.
    # See: http://www.sleuthkit.org/sleuthkit/docs/jni-docs/classorg_1_1sleuthkit_1_1datamodel_1_1_abstract_file.html
    # TODO: Add your analysis code in here.
    def process(self, file):

        skCase = Case.getCurrentCase().getSleuthkitCase();

        artID_ns_rgh_id = skCase.getArtifactTypeID("TSK_ART_NS_RGH")
        artID_ns_rgh = skCase.getArtifactType("TSK_ART_NS_RGH")

        attID_ns_rgh_gid = skCase.getAttributeType("TSK_ATT_NS_RGH_GAME")
        attID_ns_rgh_ts = skCase.getAttributeType("TSK_ATT_NS_RGS_TS")
        attID_ns_rgh_e = skCase.getAttributeType("TSK_ATT_NS_RGS_E")

        # Skip non-files
        if ((file.getType() == TskData.TSK_DB_FILES_TYPE_ENUM.UNALLOC_BLOCKS) or (file.getType() == TskData.TSK_DB_FILES_TYPE_ENUM.UNUSED_BLOCKS) or (file.isFile() == False)):
            return IngestModule.ProcessResult.OK

        if (file.getParentPath().upper() == "/SAVE/") and (file.getName().upper() == "80000000000000A2"):

            self.log(Level.INFO, "Found game history")
            self.filesFound += 1

            buf = zeros(file.getSize(), 'b')
            file.read(buf, 0, file.getSize())

            entries = re.findall("sys_info.*sequence", buf)
            for entry in entries:
                app_id = binascii.hexlify(re.search("app_id.{2}(?P<app>.{8}).*?type", entry).group('app')).upper()
                if app_id in self.gids:
                    game = self.gids[app_id]

                event = re.search("digital.event.(?P<event>.*?).sequence", entry)
                if not event:
                    event_group = "N/A"
                else:
                    event_group = event.group('event')

                timestamp = re.search("nc_recorded_at.(?P<ts>.*?).nsa_id", entry).group('ts')

                art = file.newArtifact(artID_ns_rgh_id)

                art.addAttribute(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_SET_NAME.getTypeID(), GameHistoryIngestModuleFactory.moduleName, "Nintendo Switch - Game Save"))
                art.addAttribute(BlackboardAttribute(attID_ns_rgh_gid, GameHistoryIngestModuleFactory.moduleName, game))
                art.addAttribute(BlackboardAttribute(attID_ns_rgh_ts, GameHistoryIngestModuleFactory.moduleName, timestamp))
                art.addAttribute(BlackboardAttribute(attID_ns_rgh_e, GameHistoryIngestModuleFactory.moduleName, event_group))

                # Fire an event to notify the UI and others that there is a new artifact
                IngestServices.getInstance().fireModuleDataEvent(ModuleDataEvent(GameHistoryIngestModuleFactory.moduleName, artID_ns_rgh, None));

            return IngestModule.ProcessResult.OK

    # Where any shutdown code is run and resources are freed.
    # TODO: Add any shutdown code that you need here.
    def shutDown(self):
        # As a final part of this example, we'll send a message to the ingest inbox with the number of files found (in this thread)
        message = IngestMessage.createMessage(
            IngestMessage.MessageType.DATA, GameHistoryIngestModuleFactory.moduleName, str(self.filesFound) + " recent game history found")
        ingestServices = IngestServices.getInstance().postMessage(message)
