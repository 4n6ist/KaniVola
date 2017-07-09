# JavaRAT detection and analysis for Volatility - v 1.0
# This version is limited to JavaRAT's clients 3.0 and 3.1, and maybe others 
# Author: Brian Baskin <brian@thebaskins.com>
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

import volatility.plugins.taskmods as taskmods
import volatility.win32.tasks as tasks
import volatility.utils as utils
import volatility.debug as debug
import volatility.plugins.malware.malfind as malfind
import volatility.conf as conf
import string

try:
    import yara
    has_yara = True
except ImportError:
    has_yara = False

signatures = {
    'javarat_conf' : 'rule javarat_conf {strings: $a = /port=[0-9]{1,5}SPLIT/ condition: $a}'
}

class JavaRATScan(taskmods.PSList):
    """ Extract JavaRAT Configuration from Java processes """
    def __init__(self, config, *args, **kwargs):
        taskmods.PSList.__init__(self, config, *args, **kwargs)
        config.add_option('CONFSIZE', short_option = 'C', default = 256,
                           help = 'Config file size',
                           action = 'store', type = 'int')
        config.add_option('YARAOFFSET', short_option = 'Y', default = 0,
                           help = 'YARA start offset',
                           action = 'store', type = 'int')

    def get_vad_base(self, task, address):
        for vad in task.VadRoot.traverse():
            if address >= vad.Start and address < vad.End:
                return vad.Start
        return None

    def calculate(self):
        """ Required: Runs YARA search to find hits """ 
        if not has_yara:
            debug.error('Yara must be installed for this plugin')

        addr_space = utils.load_as(self._config)
        rules = yara.compile(sources = signatures)
        for task in self.filter_tasks(tasks.pslist(addr_space)):
            if 'vmwareuser.exe' == task.ImageFileName.lower():
                continue
            if not 'java' in task.ImageFileName.lower():
                continue
            scanner = malfind.VadYaraScanner(task = task, rules = rules)
            for hit, address in scanner.scan():
                vad_base_addr = self.get_vad_base(task, address)
                yield task, address

    def make_printable(self, input):
        """ Optional: Remove non-printable chars from a string """
        input = input.replace('\x09', '')  # string.printable doesn't remove backspaces
        return ''.join(filter(lambda x: x in string.printable, input))

    def parse_structure(self, data):
        """ Optional: Parses the data into a list of values """
        struct = []
        items = data.split('SPLIT')
        for i in range(len(items) - 1):  # Iterate this way to ignore any slack data behind last 'SPLIT'
            item = self.make_printable(items[i])
            field, value = item.split('=')
            struct.append('%s: %s' % (field, value))
        return struct
    
    def render_text(self, outfd, data):
        """ Required: Parse data and display """
        delim = '-=' * 39 + '-'
        rules = yara.compile(sources = signatures)
        outfd.write('YARA rule: {0}\n'.format(signatures))
        outfd.write('YARA offset: {0}\n'.format(self._config.YARAOFFSET))
        outfd.write('Configuration size: {0}\n'.format(self._config.CONFSIZE))
        for task, address in data:  # iterate the yield values from calculate()
            outfd.write('{0}\n'.format(delim))
            outfd.write('Process: {0} ({1})\n\n'.format(task.ImageFileName, task.UniqueProcessId))
            proc_addr_space = task.get_process_address_space()
            conf_data = proc_addr_space.read(address + self._config.YARAOFFSET, self._config.CONFSIZE)
            config = self.parse_structure(conf_data)
            for i in config:
                outfd.write('\t{0}\n'.format(i))