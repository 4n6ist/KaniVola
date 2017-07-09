import volatility.plugins.common as common
import volatility.plugins.registry.registryapi as registryapi
import volatility.utils as utils

class ExHistory(common.AbstractWindowsCommand):
    """Reconstruct Exporer cache / history"""

    meta_info = {}
    meta_info['author']     = 'Sathish H Bowatta'
    meta_info['copyright']  = 'Copyright (c) 2016 Sathish H Bowatta'
    meta_info['contact']    = 'sathish.bowatta@gmail.com'
    meta_info['license']    = 'GNU GENERAL PUBLIC LICENSE 3.0'
    meta_info['os']         = 'WIN_7_x86_SP0'
    meta_info['version']    = '0.1'

    def __init__(self, config, *args, **kwargs):
        common.AbstractWindowsCommand.__init__(self, config, *args, **kwargs)
        config.add_option("EHISTRY", short_option = 'E', 
                        default = False, action = 'store_true',
                        help = 'Explorer History')
        config.add_option("RDOCS", short_option = 'R', 
                        default = False, action = 'store_true',
                        help = 'Recent Documents')
        config.add_option("SFOLDER", short_option = 'S', 
                        default = False, action = 'store_true',
                        help = 'Shell Folder History')
        config.add_option("USFOLDER", short_option = 'U', 
                        default = False, action = 'store_true',
                        help = 'User Shell Folder History')
    
    def calculate(self):
        regapi = registryapi.RegistryApi(self._config)
        regapi.set_current(hive_name = "NTUSER.DAT")

        ## Select the keys based on user input,
        keys = []
        if self._config.EHISTRY:
            key = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\WordWheelQuery"
            title= "Explorer History"
            keys.append((key, title))

        if self._config.RDOCS:
            key = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs"
            title= "Recent Documents"
            keys.append((key, title))
            
        if self._config.SFOLDER:
            key = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders"
            title= "Shell Folders"
            keys.append((key, title))
            
        if self._config.USFOLDER:
            key = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders"
            title= "User Shell Folders"
            keys.append((key, title))
                
        if not len(keys):
            key = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\WordWheelQuery"
            title= "Explorer History"
            keys.append((key, title))
            
        for key, title in keys:
            yield title
            for record in regapi.reg_yield_values(None, key = key):
                ## yield the selected registry values
                yield record[1].strip()

    def render_text(self, outfd, data):
        for record in data:
            ## write registry values into outfd
            if record in ("Explorer History", "Recent Documents", "Shell Folders", "User Shell Folders"):
                print("")
                self.table_header(outfd, [(record, "80")])
                continue
            outfd.write("{0}\n".format(record))
