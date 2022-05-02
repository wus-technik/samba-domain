#!/usr/bin/env python3
#
# Copyright (C) Matthieu Patou <mat@matws.net>  2010
# Copyright (C) Andrew Bartlett <abartlet@samba.org>  2015
#
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

"""
Change TGT user password
"""

__docformat__ = "restructuredText"


import optparse
import sys
# Allow to run from s4 source directory (without installing samba)
sys.path.insert(0, "bin/python")

import samba.getopt as options
from samba.credentials import DONT_USE_KERBEROS
from samba.auth import system_session
from samba import param
from samba.provision import find_provision_key_parameters
from samba.upgradehelpers import (get_paths,
                                  get_ldbs,
                                 update_krbtgt_account_password)

PARSER = optparse.OptionParser("chgkrbtgtpass [options]")
SAMBAOPTS = options.SambaOptions(PARSER)
PARSER.add_option_group(SAMBAOPTS)
PARSER.add_option_group(options.VersionOptions(PARSER))
CREDOPTS = options.CredentialsOptions(PARSER)
PARSER.add_option_group(CREDOPTS)

OPTS = PARSER.parse_args()[0]

LP = SAMBAOPTS.get_loadparm()
SMBCONF = LP.configfile
CREDS = CREDOPTS.get_credentials(LP)
CREDS.set_kerberos_state(DONT_USE_KERBEROS)


PATHS = get_paths(param, SMBCONF=SMBCONF)
SESSION = system_session()

LDBS = get_ldbs(PATHS, CREDS, SESSION, LP)
LDBS.startTransactions()

update_krbtgt_account_password(LDBS.sam)
LDBS.groupedCommit()
