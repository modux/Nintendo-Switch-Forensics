import jarray
import inspect
import re
from datetime import datetime
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


class PowerStateChangeIngestModuleFactory(IngestModuleFactoryAdapter):
    moduleName = "Nintendo Switch - Power State Changes"

    def getModuleDisplayName(self):
        return self.moduleName

    def getModuleDescription(self):
        return "Module to extract all recorded power state changess from the device."

    def getModuleVersionNumber(self):
        return "0.1"

    def isFileIngestModuleFactory(self):
        return True

    def createFileIngestModule(self, ingestOptions):
        return PowerStateChangeIngestModule()


class PowerStateChangeIngestModule(FileIngestModule):
    _logger = Logger.getLogger(PowerStateChangeIngestModuleFactory.moduleName)
    ARTIFACTTYPENAME_NS_POWER_STATE = "TSK_ART_NS_POWER_STATE"

    NS_POWER_STATE_ATTRIBUTES = {
        "time": ["TSK_ATT_NS_POWER_STATE_TIME", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Time"],
        "state_start": ["TSK_ATT_NS_POWER_STATE_START", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Power State Start"],
        "state_end": ["TSK_ATT_NS_POWER_STATE_STOP", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Power State Stop"],
    }

    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)

    def startUp(self, context):
        self.filesFound = 0

        skCase = Case.getCurrentCase().getSleuthkitCase()

        # Create the artifact type, if it exists then catch the error
        try:
            self.log(Level.INFO, "Begin Create New Artifact")
            artID_ns_ss = skCase.addArtifactType(self.ARTIFACTTYPENAME_NS_POWER_STATE, "Nintendo Switch - Power State Changes")
        except:
            self.log(Level.INFO, "Artifact Creation Error: NS - Power State Changes")
            artID_ns_ss = skCase.getArtifactType(self.ARTIFACTTYPENAME_NS_POWER_STATE)

        for attribute in self.NS_POWER_STATE_ATTRIBUTES.keys():
            # Create the attribute type, if it exists then catch the error
            try:
                attID_ns_gid = skCase.addArtifactAttributeType(
                    self.NS_POWER_STATE_ATTRIBUTES[attribute][0],
                    self.NS_POWER_STATE_ATTRIBUTES[attribute][1],
                    self.NS_POWER_STATE_ATTRIBUTES[attribute][2]
                )
            except:
                self.log(Level.INFO, "Attribute Creation Error: %s" % (self.NS_POWER_STATE_ATTRIBUTES[attribute][0]))

            self.NS_POWER_STATE_ATTRIBUTES[attribute].append(skCase.getAttributeType(self.NS_POWER_STATE_ATTRIBUTES[attribute][0]))

        pass

    def process(self, file):
        skCase = Case.getCurrentCase().getSleuthkitCase()
        ARTID_NS_POWER_STATE = skCase.getArtifactTypeID(self.ARTIFACTTYPENAME_NS_POWER_STATE)

        power_states = []

        skCase = Case.getCurrentCase().getSleuthkitCase()

        # Skip non-files
        if ((file.getType() == TskData.TSK_DB_FILES_TYPE_ENUM.UNALLOC_BLOCKS)
                or (file.getType() == TskData.TSK_DB_FILES_TYPE_ENUM.UNUSED_BLOCKS)
                or (file.isFile() is False)):
            return IngestModule.ProcessResult.OK

        blackboard = Case.getCurrentCase().getServices().getBlackboard()

        if (file.getName().lower() == "80000000000000a1"):
            artifactList = file.getArtifacts(ARTID_NS_POWER_STATE)

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
                regex = "nc_started_at.(?P<datetime>[0-9: -]{19}).power_state_start.(?P<state_start>[a-zA-Z]+).power_state_end.(?P<state_end>[a-zA-Z]+)"
                x = re.finditer(regex, currentBuffer)
                for state_change in x:
                    timestamp = datetime.strptime(state_change.group('datetime'), '%Y-%m-%d %H:%M:%S')
                    state_start = state_change.group('state_start')
                    state_end = state_change.group('state_end')
                    power_states.append((timestamp, state_start, state_end))

            for (timestamp, state_start, state_end) in power_states:
                # Don't add to blackboard if the artifact already exists
                self.log(Level.INFO, str(len(artifactList)))
                for artifact in artifactList:
                    artifact_time = artifact.getAttribute(self.NS_POWER_STATE_ATTRIBUTES["time"][3])
                    artifact_state_start = artifact.getAttribute(self.NS_POWER_STATE_ATTRIBUTES["state_start"][3])
                    artifact_state_end = artifact.getAttribute(self.NS_POWER_STATE_ATTRIBUTES["state_end"][3])
                    if artifact_time.getValueString() == str(timestamp):
                        if artifact_state_start.getValueString() == state_start:
                            if artifact_state_end.getValueString() == state_end:
                                return IngestModule.ProcessResult.OK

                art = file.newArtifact(ARTID_NS_POWER_STATE)
                art.addAttribute(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_SET_NAME.getTypeID(), PowerStateChangeIngestModuleFactory.moduleName, "Nintendo Switch - Power State Changes"))
                art.addAttribute(BlackboardAttribute(self.NS_POWER_STATE_ATTRIBUTES["time"][3], PowerStateChangeIngestModuleFactory.moduleName, str(timestamp)))
                art.addAttribute(BlackboardAttribute(self.NS_POWER_STATE_ATTRIBUTES["state_start"][3], PowerStateChangeIngestModuleFactory.moduleName, state_start))
                art.addAttribute(BlackboardAttribute(self.NS_POWER_STATE_ATTRIBUTES["state_end"][3], PowerStateChangeIngestModuleFactory.moduleName, state_end))

                try:
                    # index the artifact for keyword search
                    blackboard.indexArtifact(art)
                except Blackboard.BlackboardException:
                    self.log(Level.SEVERE, "Error indexing artifact " + art.getDisplayName())

                IngestServices.getInstance().fireModuleDataEvent(ModuleDataEvent(PowerStateChangeIngestModuleFactory.moduleName, skCase.getArtifactType(self.ARTIFACTTYPENAME_NS_POWER_STATE), None))

            return IngestModule.ProcessResult.OK

    def shutDown(self):
        message = IngestMessage.createMessage(
            IngestMessage.MessageType.DATA, PowerStateChangeIngestModuleFactory.moduleName,
            str(self.filesFound) + " files found")
        _ = IngestServices.getInstance().postMessage(message)
