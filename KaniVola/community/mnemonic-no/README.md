pdblist
=========

pdblist is a plugin for the [Volatility Memory Forensics Platform](http://www.volatilityfoundation.org/) to extract and list the PDB info of running processes and services.

The PDB string may contain information about the build environment, such as username.

Also, in some cases, the PDB file name is attempted hidden (overwritten after
compile) but the debug section is still there. An empty PDB filename is a
potential warning flag.

## Usage

```bash
% vol.py pdblist --output-file=pdblist.txt [--renamed_only]
```

--renamed_only tests if base name minus extensions is not matching on lowercase. If they are different the plugin will output.


## Installation

Copy the pdblist.py to your plugins directory or point volatility to your checkout directory

e.g.

`% vol.py --plugins=/home/geir/src/pdblist pdblist`

## Known issues

See the [BUGS.md](BUGS.md) file.

## Contributing

See the [CONTRIBUTING.md](CONTRIBUTING.md) file.

## Credits

REFERENCES:
1. Starodumov, O (2010). Matching debug information.
   Retrieved from:
     http://www.debuginfo.com/articles/debuginfomatch.html
2. MSDN Microsoft (2009). GUID Data Type
   Retrieved from:
     https://msdn.microsoft.com/en-us/library/dd354925.aspx

## License

pdblist is released under the ISC License. See the bundled LICENSE file for
details.
