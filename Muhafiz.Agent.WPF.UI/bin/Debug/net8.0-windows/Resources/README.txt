Place third-party helper binaries in this folder before building the agent.

Expected files:
- yara64.exe (or compatible) for on-host YARA scanning.

All files under this directory are copied to the agent's output and then deployed to %PROGRAMDATA%\Muhafiz during bootstrap.
