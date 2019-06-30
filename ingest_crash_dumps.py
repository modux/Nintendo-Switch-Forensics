# Simple Nintendo Switch crash dump ingest module for Autopsy.

import os
import re
import shutil
import inspect
import msgpack
import tempfile
import subprocess
from jarray import zeros
from java.lang import System
from datetime import datetime
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


class CrashDumpIngestModuleFactory(IngestModuleFactoryAdapter):
    # Factory that defines the name and details of the module and allows Autopsy
    # to create instances of the modules that will do the anlaysis.

    # Will be shown in module list, logs, etc.
    moduleName = "Nintendo Switch - Crash Dumps"

    def getModuleDisplayName(self):
        return self.moduleName

    # TODO: Give it a description
    def getModuleDescription(self):
        return "Module that pulls out crash dumps from a Nintendo Switch."

    def getModuleVersionNumber(self):
        return "0.1"

    # Return true if module wants to get called for each file
    def isFileIngestModuleFactory(self):
        return True

    # can return null if isFileIngestModuleFactory returns false
    def createFileIngestModule(self, ingestOptions):
        return CrashDumpIngestModule()


# File-level ingest module.  One gets created per thread.
# TODO: Rename this to something more specific. Could just remove "Factory" from above name.
# Looks at the attributes of the passed in file.
class CrashDumpIngestModule(FileIngestModule):

    _logger = Logger.getLogger(CrashDumpIngestModuleFactory.moduleName)

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
            artID_ns_cd = skCase.addArtifactType("TSK_ART_NS_CD", "Nintendo Switch - Crash Dumps")
        except:
            self.log(Level.INFO, "Artifact Creation Error: NS - Crash Dumps")

        try:
            attID_ns_cd_apssid = skCase.addArtifactAttributeType('TSK_ATT_CD_APSSID', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Access Point SSID")
        except:
            self.log(Level.INFO, "Attribute Creation Error: AccessPointSSID")

        try:
            attID_ns_cd_apsec = skCase.addArtifactAttributeType('TSK_ATT_CD_APSEC', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Access Point Security Type")
        except:
            self.log(Level.INFO, "Attribute Creation Error: AccessPointSecurityType")

        try:
            attID_ns_cd_appt = skCase.addArtifactAttributeType('TSK_ATT_CD_APPT', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Application Title")
        except:
            self.log(Level.INFO, "Attribute Creation Error: ApplicationTitle")

        try:
            attID_ns_cd_batc = skCase.addArtifactAttributeType('TSK_ATT_CD_BATC', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Battery Charge Percent")
        except:
            self.log(Level.INFO, "Attribute Creation Error: BatteryChargePercent")

        try:
            attID_ns_cd_charge = skCase.addArtifactAttributeType('TSK_ATT_CD_CHARGE', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Charge Enabled")
        except:
            self.log(Level.INFO, "Attribute Creation Error: ChargeEnabled")

        try:
            attID_ns_cd_con = skCase.addArtifactAttributeType('TSK_ATT_CD_CON', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Connection Status")
        except:
            self.log(Level.INFO, "Attribute Creation Error: ConnectionStatus")

        try:
            attID_ns_cd_ip = skCase.addArtifactAttributeType('TSK_ATT_CD_IP', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "IP Address")
        except:
            self.log(Level.INFO, "Attribute Creation Error: CurrentIPAddress")

        try:
            attID_ns_cd_lang = skCase.addArtifactAttributeType('TSK_ATT_CD_LANG', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Language")
        except:
            self.log(Level.INFO, "Attribute Creation Error: CurrentLanguage")

        try:
            attID_ns_cd_cpower = skCase.addArtifactAttributeType('TSK_ATT_CD_CPOWER', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Current Power State")
        except:
            self.log(Level.INFO, "Attribute Creation Error: CurrentSystemPowerState")

        try:
            attID_ns_cd_dpower = skCase.addArtifactAttributeType('TSK_ATT_CD_DPOWER', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Destination Power State")
        except:
            self.log(Level.INFO, "Attribute Creation Error: DestinationSystemPowerState")

        try:
            attID_ns_cd_ltime = skCase.addArtifactAttributeType('TSK_ATT_CD_LTIME', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Time Since Launch")
        except:
            self.log(Level.INFO, "Attribute Creation Error: ElapsedTimeSinceInitialLaunch")

        try:
            attID_ns_cd_atime = skCase.addArtifactAttributeType('TSK_ATT_CD_ATIME', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Time Since Last Awake")
        except:
            self.log(Level.INFO, "Attribute Creation Error: ElapsedTimeSinceLastAwake")

        try:
            attID_ns_cd_ptime = skCase.addArtifactAttributeType('TSK_ATT_CD_PTIME', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Time Since Last Power On")
        except:
            self.log(Level.INFO, "Attribute Creation Error: ElapsedTimeSincePowerOn")

        try:
            attID_ns_cd_errc = skCase.addArtifactAttributeType('TSK_ATT_CD_ERRC', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Error Code")
        except:
            self.log(Level.INFO, "Attribute Creation Error: ErrorCode")

        try:
            attID_ns_cd_gip = skCase.addArtifactAttributeType('TSK_ATT_CD_GIP', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Gateway IP Address")
        except:
            self.log(Level.INFO, "Attribute Creation Error: GatewayIPAddress")

        try:
            attID_ns_cd_batn = skCase.addArtifactAttributeType('TSK_ATT_CD_BATN', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Internal Battery #")
        except:
            self.log(Level.INFO, "Attribute Creation Error: InternalBatteryLotNumber")

        try:
            attID_ns_cd_monh = skCase.addArtifactAttributeType('TSK_ATT_CD_MONH', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Monitor Height")
        except:
            self.log(Level.INFO, "Attribute Creation Error: MonitorCurrentHeight")

        try:
            attID_ns_cd_monw = skCase.addArtifactAttributeType('TSK_ATT_CD_MONW', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Monitor Width")
        except:
            self.log(Level.INFO, "Attribute Creation Error: MonitorCurrentWidth")

        try:
            attID_ns_cd_monm = skCase.addArtifactAttributeType('TSK_ATT_CD_MONM', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Monitor Manufacturer")
        except:
            self.log(Level.INFO, "Attribute Creation Error: MonitorManufactureCode")

        try:
            attID_ns_cd_mons = skCase.addArtifactAttributeType('TSK_ATT_CD_MONS', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Monitor Serial #")
        except:
            self.log(Level.INFO, "Attribute Creation Error: MonitorSerialNumber")

        try:
            attID_ns_cd_nfs = skCase.addArtifactAttributeType('TSK_ATT_CD_NFS', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "NAND Free Space")
        except:
            self.log(Level.INFO, "Attribute Creation Error: NANDFreeSpace")

        try:
            attID_ns_cd_nts = skCase.addArtifactAttributeType('TSK_ATT_CD_NTS', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "NAND Total Size")
        except:
            self.log(Level.INFO, "Attribute Creation Error: NANDTotalSize")

        try:
            attID_ns_cd_nxmac = skCase.addArtifactAttributeType('TSK_ATT_CD_NXMAC', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Device MAC Address")
        except:
            self.log(Level.INFO, "Attribute Creation Error: NXMacAddress")

        try:
            attID_ns_cd_ot = skCase.addArtifactAttributeType('TSK_ATT_CD_OT', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Occurrence Tick")
        except:
            self.log(Level.INFO, "Attribute Creation Error: OccurrenceTick")

        try:
            attID_ns_cd_ots = skCase.addArtifactAttributeType('TSK_ATT_CD_OTS', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Occurrence Timestamp")
        except:
            self.log(Level.INFO, "Attribute Creation Error: OccurrenceTimestamp")

        try:
            attID_ns_cd_osv = skCase.addArtifactAttributeType('TSK_ATT_CD_OSV', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Os Version")
        except:
            self.log(Level.INFO, "Attribute Creation Error: OsVersion")

        try:
            attID_ns_cd_dnsp = skCase.addArtifactAttributeType('TSK_ATT_CD_DNSP', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Priority DNS IP")
        except:
            self.log(Level.INFO, "Attribute Creation Error: PriorityDNSIPAddress")

        try:
            attID_ns_cd_region = skCase.addArtifactAttributeType('TSK_ATT_CD_REGION', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Device Region")
        except:
            self.log(Level.INFO, "Attribute Creation Error: RegionSetting")

        try:
            attID_ns_cd_rid = skCase.addArtifactAttributeType('TSK_ATT_CD_RID', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Crash Dump ID")
        except:
            self.log(Level.INFO, "Attribute Creation Error: ReportIdentifier")

        try:
            attID_ns_cd_rappt = skCase.addArtifactAttributeType('TSK_ATT_CD_RAPPT', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Running App Title")
        except:
            self.log(Level.INFO, "Attribute Creation Error: RunningApplicationTitle")

        try:
            attID_ns_cd_nxsn = skCase.addArtifactAttributeType('TSK_ATT_CD_NXSN', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Device Serial #")
        except:
            self.log(Level.INFO, "Attribute Creation Error: SerialNumber")

        try:
            attID_ns_cd_netm = skCase.addArtifactAttributeType('TSK_ATT_CD_NETM', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Subnet Mask")
        except:
            self.log(Level.INFO, "Attribute Creation Error: SubnetMask")

        try:
            attID_ns_cd_tz = skCase.addArtifactAttributeType('TSK_ATT_CD_TZ', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Time Zone")
        except:
            self.log(Level.INFO, "Attribute Creation Error: TimeZone")

        try:
            attID_ns_cd_vout = skCase.addArtifactAttributeType('TSK_ATT_CD_VOUT', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Video Output Setting")
        except:
            self.log(Level.INFO, "Attribute Creation Error: VideoOutputSetting")

        try:
            attID_ns_cd_apmac = skCase.addArtifactAttributeType('TSK_ATT_CD_APMAC', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "AP MAC Address")
        except:
            self.log(Level.INFO, "Attribute Creation Error: WirelessAPMacAddress")

        self.tmp_path = os.path.join(tempfile.gettempdir(), "switch_crash_dumps")
        self.hac_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dependencies", "hactoolnet.exe")

        if not os.path.exists(self.tmp_path):
            os.mkdir(self.tmp_path)

        if not os.path.exists(self.hac_path):
            raise IngestModuleException("hactoolnet.exe was not found in module folder")

        # Throw an IngestModule.IngestModuleException exception if there was a problem setting up
        # raise IngestModuleException(IngestModule(), "Oh No!")
        pass

    # Where the analysis is done.  Each file will be passed into here.
    # The 'file' object being passed in is of type org.sleuthkit.datamodel.AbstractFile.
    # See: http://www.sleuthkit.org/sleuthkit/docs/jni-docs/classorg_1_1sleuthkit_1_1datamodel_1_1_abstract_file.html
    # TODO: Add your analysis code in here.
    def process(self, file):

        skCase = Case.getCurrentCase().getSleuthkitCase()

        artID_ns_cd = skCase.getArtifactType("TSK_ART_NS_CD")
        artID_ns_cd_id = skCase.getArtifactTypeID("TSK_ART_NS_CD")

        attID_ns_cd_apssid = skCase.getAttributeType("TSK_ATT_CD_APSSID")
        attID_ns_cd_apsec = skCase.getAttributeType("TSK_ATT_CD_APSEC")
        attID_ns_cd_appt = skCase.getAttributeType("TSK_ATT_CD_APPT")
        attID_ns_cd_batc = skCase.getAttributeType("TSK_ATT_CD_BATC")
        attID_ns_cd_charge = skCase.getAttributeType("TSK_ATT_CD_CHARGE")
        attID_ns_cd_con = skCase.getAttributeType("TSK_ATT_CD_CON")
        attID_ns_cd_ip = skCase.getAttributeType("TSK_ATT_CD_IP")
        attID_ns_cd_lang = skCase.getAttributeType("TSK_ATT_CD_LANG")
        attID_ns_cd_cpower = skCase.getAttributeType("TSK_ATT_CD_CPOWER")
        attID_ns_cd_dpower = skCase.getAttributeType("TSK_ATT_CD_DPOWER")
        attID_ns_cd_ltime = skCase.getAttributeType("TSK_ATT_CD_LTIME")
        attID_ns_cd_atime = skCase.getAttributeType("TSK_ATT_CD_ATIME")
        attID_ns_cd_ptime = skCase.getAttributeType("TSK_ATT_CD_PTIME")
        attID_ns_cd_errc = skCase.getAttributeType("TSK_ATT_CD_ERRC")
        attID_ns_cd_gip = skCase.getAttributeType("TSK_ATT_CD_GIP")
        attID_ns_cd_batn = skCase.getAttributeType("TSK_ATT_CD_BATN")
        attID_ns_cd_monh = skCase.getAttributeType("TSK_ATT_CD_MONH")
        attID_ns_cd_monw = skCase.getAttributeType("TSK_ATT_CD_MONW")
        attID_ns_cd_monm = skCase.getAttributeType("TSK_ATT_CD_MONM")
        attID_ns_cd_mons = skCase.getAttributeType("TSK_ATT_CD_MONS")
        attID_ns_cd_nfs = skCase.getAttributeType("TSK_ATT_CD_NFS")
        attID_ns_cd_nts = skCase.getAttributeType("TSK_ATT_CD_NTS")
        attID_ns_cd_nxmac = skCase.getAttributeType("TSK_ATT_CD_NXMAC")
        attID_ns_cd_ot = skCase.getAttributeType("TSK_ATT_CD_OT")
        attID_ns_cd_ots = skCase.getAttributeType("TSK_ATT_CD_OTS")
        attID_ns_cd_osv = skCase.getAttributeType("TSK_ATT_CD_OSV")
        attID_ns_cd_dnsp = skCase.getAttributeType("TSK_ATT_CD_DNSP")
        attID_ns_cd_region = skCase.getAttributeType("TSK_ATT_CD_REGION")
        attID_ns_cd_rid = skCase.getAttributeType("TSK_ATT_CD_RID")
        attID_ns_cd_rappt = skCase.getAttributeType("TSK_ATT_CD_RAPPT")
        attID_ns_cd_nxsn = skCase.getAttributeType("TSK_ATT_CD_NXSN")
        attID_ns_cd_netm = skCase.getAttributeType("TSK_ATT_CD_NETM")
        attID_ns_cd_tz = skCase.getAttributeType("TSK_ATT_CD_TZ")
        attID_ns_cd_vout = skCase.getAttributeType("TSK_ATT_CD_VOUT")
        attID_ns_cd_apmac = skCase.getAttributeType("TSK_ATT_CD_APMAC")

        # Skip non-files
        if ((file.getType() == TskData.TSK_DB_FILES_TYPE_ENUM.UNALLOC_BLOCKS) or (file.getType() == TskData.TSK_DB_FILES_TYPE_ENUM.UNUSED_BLOCKS) or (file.isFile() == False)):
            return IngestModule.ProcessResult.OK

        if (file.getParentPath().upper() == "/SAVE/") and (file.getName().upper() == "80000000000000D1"):

            self.log(Level.INFO, "Found crash dump save")
            self.filesFound += 1

            buf = zeros(file.getSize(), 'b')
            file.read(buf, 0, file.getSize())

            tmp_file_path = os.path.join(self.tmp_path, file.getName())

            with open(tmp_file_path, 'wb+') as tmp_file:
                tmp_file.write(buf)

            hac_cmd = [self.hac_path, "-t", "save", "--outdir", self.tmp_path, tmp_file_path]
            subprocess.call(hac_cmd)

            crash_files = [os.path.join(self.tmp_path, f) for f in os.listdir(self.tmp_path) if os.path.isfile(os.path.join(self.tmp_path, f)) and re.match(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", f)]

            for msgpack_file in crash_files:
                with open(msgpack_file, "rb") as infile:
                    data = msgpack.unpack(infile)

                # Don't add to blackboard if already exists
                artifactList = file.getArtifacts(artID_ns_cd_id)
                cd_ids = []
                for artifact in artifactList:
                    cd_ids.append(artifact.getAttribute(attID_ns_cd_rid).getValueString())
                if data["ReportIdentifier"] in cd_ids:
                    return IngestModule.ProcessResult.OK

                art = file.newArtifact(artID_ns_cd_id)

                art.addAttribute(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_SET_NAME.getTypeID(), CrashDumpIngestModuleFactory.moduleName, "Nintendo Switch - Crash Dumps"))
                if "AccessPointSSID" in data:
                    art.addAttribute(BlackboardAttribute(attID_ns_cd_apssid, CrashDumpIngestModuleFactory.moduleName, str(data["AccessPointSSID"])))
                if "AccessPointSecurityType" in data:
                    art.addAttribute(BlackboardAttribute(attID_ns_cd_apsec, CrashDumpIngestModuleFactory.moduleName, str(data["AccessPointSecurityType"])))
                if "ApplicationTitle" in data:
                    art.addAttribute(BlackboardAttribute(attID_ns_cd_appt, CrashDumpIngestModuleFactory.moduleName, str(data["ApplicationTitle"])))
                if "BatteryChargePercent" in data:
                    art.addAttribute(BlackboardAttribute(attID_ns_cd_batc, CrashDumpIngestModuleFactory.moduleName, "%.2f%%" % (data["BatteryChargePercent"] / 1000.0)))
                if "ChargeEnabled" in data:
                    art.addAttribute(BlackboardAttribute(attID_ns_cd_charge, CrashDumpIngestModuleFactory.moduleName, str(data["ChargeEnabled"])))
                if "ConnectionStatus" in data:
                    art.addAttribute(BlackboardAttribute(attID_ns_cd_con, CrashDumpIngestModuleFactory.moduleName, str(data["ConnectionStatus"])))
                if "CurrentIPAddress" in data:
                    art.addAttribute(BlackboardAttribute(attID_ns_cd_ip, CrashDumpIngestModuleFactory.moduleName, str(data["CurrentIPAddress"])))
                if "CurrentLanguage" in data:
                    art.addAttribute(BlackboardAttribute(attID_ns_cd_lang, CrashDumpIngestModuleFactory.moduleName, str(data["CurrentLanguage"])))
                if "CurrentSystemPowerState" in data:
                    art.addAttribute(BlackboardAttribute(attID_ns_cd_cpower, CrashDumpIngestModuleFactory.moduleName, str(data["CurrentSystemPowerState"])))
                if "DestinationSystemPowerState" in data:
                    art.addAttribute(BlackboardAttribute(attID_ns_cd_dpower, CrashDumpIngestModuleFactory.moduleName, str(data["DestinationSystemPowerState"])))
                if "ElapsedTimeSinceInitialLaunch" in data:
                    art.addAttribute(BlackboardAttribute(attID_ns_cd_ltime, CrashDumpIngestModuleFactory.moduleName, str(data["ElapsedTimeSinceInitialLaunch"])))
                if "ElapsedTimeSinceLastAwake" in data:
                    art.addAttribute(BlackboardAttribute(attID_ns_cd_atime, CrashDumpIngestModuleFactory.moduleName, str(data["ElapsedTimeSinceLastAwake"])))
                if "ElapsedTimeSincePowerOn" in data:
                    art.addAttribute(BlackboardAttribute(attID_ns_cd_ptime, CrashDumpIngestModuleFactory.moduleName, str(data["ElapsedTimeSincePowerOn"])))
                if "ErrorCode" in data:
                    art.addAttribute(BlackboardAttribute(attID_ns_cd_errc, CrashDumpIngestModuleFactory.moduleName, str(data["ErrorCode"])))
                if "GatewayIPAddress" in data:
                    art.addAttribute(BlackboardAttribute(attID_ns_cd_gip, CrashDumpIngestModuleFactory.moduleName, str(data["GatewayIPAddress"])))
                if "InternalBatteryLotNumber" in data:
                    art.addAttribute(BlackboardAttribute(attID_ns_cd_batn, CrashDumpIngestModuleFactory.moduleName, str(data["InternalBatteryLotNumber"])))
                if "MonitorCurrentHeight" in data:
                    art.addAttribute(BlackboardAttribute(attID_ns_cd_monh, CrashDumpIngestModuleFactory.moduleName, str(data["MonitorCurrentHeight"])))
                if "MonitorCurrentWidth" in data:
                    art.addAttribute(BlackboardAttribute(attID_ns_cd_monw, CrashDumpIngestModuleFactory.moduleName, str(data["MonitorCurrentWidth"])))
                if "MonitorManufactureCode" in data:
                    art.addAttribute(BlackboardAttribute(attID_ns_cd_monm, CrashDumpIngestModuleFactory.moduleName, str(data["MonitorManufactureCode"])))
                if "MonitorSerialNumber" in data:
                    art.addAttribute(BlackboardAttribute(attID_ns_cd_mons, CrashDumpIngestModuleFactory.moduleName, str(data["MonitorSerialNumber"])))
                if "NANDFreeSpace" in data:
                    art.addAttribute(BlackboardAttribute(attID_ns_cd_nfs, CrashDumpIngestModuleFactory.moduleName, str(data["NANDFreeSpace"])))
                if "NANDTotalSize" in data:
                    art.addAttribute(BlackboardAttribute(attID_ns_cd_nts, CrashDumpIngestModuleFactory.moduleName, str(data["NANDTotalSize"])))
                if "NXMacAddress" in data:
                    art.addAttribute(BlackboardAttribute(attID_ns_cd_nxmac, CrashDumpIngestModuleFactory.moduleName, str(data["NXMacAddress"])))
                if "OccurrenceTick" in data:
                    art.addAttribute(BlackboardAttribute(attID_ns_cd_ot, CrashDumpIngestModuleFactory.moduleName, str(data["OccurrenceTick"])))
                if "OccurrenceTimestamp" in data:
                    OccurrenceTimestamp = datetime.fromtimestamp(data["OccurrenceTimestamp"]).strftime('%H:%M %d/%m/%Y')
                    art.addAttribute(BlackboardAttribute(attID_ns_cd_ots, CrashDumpIngestModuleFactory.moduleName, str(OccurrenceTimestamp)))
                if "OsVersion" in data:
                    art.addAttribute(BlackboardAttribute(attID_ns_cd_osv, CrashDumpIngestModuleFactory.moduleName, str(data["OsVersion"])))
                if "PriorityDNSIPAddress" in data:
                    art.addAttribute(BlackboardAttribute(attID_ns_cd_dnsp, CrashDumpIngestModuleFactory.moduleName, str(data["PriorityDNSIPAddress"])))
                if "RegionSetting" in data:
                    art.addAttribute(BlackboardAttribute(attID_ns_cd_region, CrashDumpIngestModuleFactory.moduleName, str(data["RegionSetting"])))
                if "ReportIdentifier" in data:
                    art.addAttribute(BlackboardAttribute(attID_ns_cd_rid, CrashDumpIngestModuleFactory.moduleName, str(data["ReportIdentifier"])))
                if "RunningApplicationTitle" in data:
                    art.addAttribute(BlackboardAttribute(attID_ns_cd_rappt, CrashDumpIngestModuleFactory.moduleName, str(data["RunningApplicationTitle"])))
                if "SerialNumber" in data:
                    art.addAttribute(BlackboardAttribute(attID_ns_cd_nxsn, CrashDumpIngestModuleFactory.moduleName, str(data["SerialNumber"])))
                if "SubnetMask" in data:
                    art.addAttribute(BlackboardAttribute(attID_ns_cd_netm, CrashDumpIngestModuleFactory.moduleName, str(data["SubnetMask"])))
                if "TimeZone" in data:
                    art.addAttribute(BlackboardAttribute(attID_ns_cd_tz, CrashDumpIngestModuleFactory.moduleName, str(data["TimeZone"])))
                if "VideoOutputSetting" in data:
                    art.addAttribute(BlackboardAttribute(attID_ns_cd_vout, CrashDumpIngestModuleFactory.moduleName, str(data["VideoOutputSetting"])))
                if "WirelessAPMacAddress" in data:
                    art.addAttribute(BlackboardAttribute(attID_ns_cd_apmac, CrashDumpIngestModuleFactory.moduleName, str(data["WirelessAPMacAddress"])))
                # Fire an event to notify the UI and others that there is a new artifact
                IngestServices.getInstance().fireModuleDataEvent(ModuleDataEvent(CrashDumpIngestModuleFactory.moduleName, artID_ns_cd, None));

            return IngestModule.ProcessResult.OK

    # Where any shutdown code is run and resources are freed.
    # TODO: Add any shutdown code that you need here.
    def shutDown(self):
        # As a final part of this example, we'll send a message to the ingest inbox with the number of files found (in this thread)
        message = IngestMessage.createMessage(
            IngestMessage.MessageType.DATA, CrashDumpIngestModuleFactory.moduleName, str(self.filesFound) + " crash dumps found")
        ingestServices = IngestServices.getInstance().postMessage(message)

        # remove temp dir after use
        if os.path.exists(self.tmp_path):
            shutil.rmtree(self.tmp_path)
