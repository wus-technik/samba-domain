#!/usr/bin/env python3
#
# enabled the Recycle Bin optional feature
#
# https://gitlab.com/samba-team/samba/-/blob/master/source4/scripting/bin/enablerecyclebin
# python3 enablerecylcebin /var/lib/samba/private/sam.ldb
#
import optparse
import sys
# Find right directory when running from source tree
sys.path.insert(0, "bin/python")
import samba
import ldb
from samba import getopt as OPTIONS, Ldb
from ldb import SCOPE_BASE
from samba.auth import system_session

PARSER = optparse.OptionParser("enablerecyclebin <URL>")
SAMBAOPTS = OPTIONS.SambaOptions(PARSER)
PARSER.add_option_group(SAMBAOPTS)
credopts = OPTIONS.CredentialsOptions(PARSER)
PARSER.add_option_group(credopts)
PARSER.add_option_group(OPTIONS.VersionOptions(PARSER))

OPTS, ARGS = PARSER.parse_args()
OPTS.dump_all = True

if len(ARGS) != 1:
    PARSER.print_usage()
    sys.exit(1)

URL = ARGS[0]

LP_CTX = SAMBAOPTS.get_loadparm()

CREDS = credopts.get_credentials(LP_CTX)
SAM_LDB = Ldb(URL, session_info=system_session(), credentials=CREDS, lp=LP_CTX)

# get the ROOTDSE
RES = SAM_LDB.search(base="", expression="", scope=SCOPE_BASE, attrs=["configurationNamingContext"])
ROOTDSE = RES[0]

CONFIGBASE=ROOTDSE["configurationNamingContext"]

# enable the feature
MSG = ldb.Message()
MSG.dn = ldb.Dn(SAM_LDB, "")
MSG["enableOptionalFeature"] = ldb.MessageElement(
     "CN=Partitions," +  str(CONFIGBASE) + ":766ddcd8-acd0-445e-f3b9-a7f9b6744f2a",
    ldb.FLAG_MOD_ADD, "enableOptionalFeature")
RES = SAM_LDB.modify(MSG)

print("Recycle Bin feature enabled")
