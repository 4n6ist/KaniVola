# DarkComet Rat Config Dumper and analysis for Volatility 2.0
#
# Version 1.0
# Author: DFIR N00B <dfirn00b@gmail.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or (at
# your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA

import volatility.utils as utils
import volatility.plugins.taskmods as taskmods
import volatility.debug as debug
import volatility.win32.tasks as tasks
import volatility.plugins.malware.malfind as malfind

try:
    import yara
    has_yara = True
except ImportError:
    has_yara = False


sigs = {
    'darkcomet_config': 'rule darkcomet_config {strings: $a = "#BEGIN DARKCOMET" ascii nocase condition: $a}',
    'darkcomet_config_stop': 'rule darkcomet_config_stop {strings: $a = "#EOF DARKCOMET DATA --" ascii nocase condition: $a}',
}

class DarkCometConfigDump(taskmods.PSList):
    """Dump darkcomet rat config"""

    def get_vad_base(self, task, address):
        """ Get the VAD starting address"""

        for vad in task.VadRoot.traverse():
            if address >= vad.Start and address < vad.End:
                return vad.Start
        return None

    def calculate(self):
        if not has_yara:
            debug.error("Yara must be installed for this plugin")

        addr_space = utils.load_as(self._config)
        rules = yara.compile(sources=sigs)

        for task in self.filter_tasks(tasks.pslist(addr_space)):
            scanner = malfind.VadYaraScanner(task=task, rules=rules)
            config = False
            start_add = False
            stop_add = False
            for hit, address in scanner.scan():
                if str(hit) == 'darkcomet_config':
                    config = hit
                    start_add = address
                if str(hit) == 'darkcomet_config_stop':
                    stop_add = address + 0x20 #Add 0x20 to address to get all of EOF statement

            #if we have a hit on all three sigs lets yield
            if config and start_add and stop_add:
                yield task,config,start_add,stop_add
            else:
                pass

    def render_text(self, outfd, data):
        self.table_header(outfd, [("Name", "20"),
                                  ("PID", "8"),
                                  ("YARA RULE", "20")])
        for task,hit,start_add,stop_add in data:
            self.table_row(outfd, task.ImageFileName, task.UniqueProcessId, hit)
            proc_addr_space = task.get_process_address_space()
            dk_config = proc_addr_space.read(start_add, stop_add - start_add)
            if dk_config:
                outfd.write("\n\nDarkComet Config Dump Below\n\n")
                outfd.write(dk_config+'\n\n')
            else:
                #Due to potential yara hits in memory there is a chance the start/end address could be way off
                #Lets go wit the start address and dump 400 bytes after it. If more is needed either use volshell
                #or change the plugin :)
                outfd.write("\n\nDarkComet Config Dump Below\n\n")
                outfd.write(proc_addr_space.read(start_add, 400)+"\n\n")
