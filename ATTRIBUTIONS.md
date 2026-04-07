# attributions

## direct dependencies

**jfjallid/go-smb2**
SMB2/3 client implementation in Go. does the actual heavy lifting.
https://github.com/jfjallid/go-smb

**fatih/color**
terminal color output.
https://github.com/fatih/color

**rs/zerolog**
super duper structured logging.
https://github.com/rs/zerolog

**spf13/pflag**
flag handling. it's always about flags
https://github.com/spf13/pflag

## acknowledgements

the entire premise of this tool exists because smbmap and netexec both read ACLs instead of testing writes. credit to whoever first noticed that ACL-based enumeration lies you know who you are.

## author

Gato (investigato)
https://github.com/investigato