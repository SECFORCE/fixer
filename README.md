Fixer
==

Authors:
----

SECFORCE
  
  Thanos Polychronis (@t_polychronis)
  
  Lorenzo Vogelsang (@ptrac3)

You Gotta Hack That
  
  Felix Ryan (@gotta_hack)

Description:
----

Fixer™ is a Python command-line tool which simplifies and enhances FIX security testing by delivering a more customisable and automated Fix fuzzing process.


Requirements:
----

Wireshark or TCPDump

Fixer will use as input a TCPDump or Wireshark capture of a legitimate fix Login conversation in raw format. 
The tool will then process the .RAW file exctracting and parsing FIX messages which will be fuzzed by the tool.


Options:
----

[REQUIRED] `--host`               Remote FIX server IP

[REQUIRED] `--port`               Remote FIX server listening port

[REQUIRED] `--input-file`         Path of the captured .RAW file with a valid FIX login sequence

[REQUIRED] `--csv`                Path for the output CSV log file

`--seq-start`                     The sequence ID to start sending FIX messages with

`--fuzz`                          Path of the file containing the payloads for fuzzing

`--param`                         Comma separeted FIX fields to fuzz. If none were provided every field will be fuzzed

`--auto-fuzz length step`         It enables the auto-fuzz mode which generates UTF-8 payloads on the fly accordingly to the length and step values that were passed

`--sequential-fuzz`               Effectively a brute forcer

`--no-fuzz`                       Just send the original FIX messages to show that the tool has connectivity and everything is working correctly

Please also consider that --fuzz and --auto-fuzz are mutually exclusive parameters.


Usage Example:
----


**Auto-FUZZ™**


`python fix.py --host=127.0.0.1 --port=11310 --input-file=Demo/demo.raw --csv-log csv_log.txt --auto-fuzz 40 5 --param 11,38`

With this command the tool will automatically login to the remote FIX server using the provided demo.raw file. After the login process the tool will then start to randomly generate UTF-8 payloads to be embedded into each subsequent FIX request into the 11 and 38 FIX fields (please note that the UTF-8 paylaods are generated accordingly to the length and step that were passed).


**Normal-Mode**


`fix.py --host=127.0.0.1 --port=11310 --input-file=Demo/demo.raw --csv-log csv_log.txt --fuzz /tmp/payloads.fuzz --param 11,38`

With this command the tool will automatically login to the remote FIX server using the provided demo.raw file. After the login process the tool will then start to fuzz the 11 and 38 FIX fields using the payloads contained into the payloads.fuzz file.

If no parameters are specified, then Fixer will fuzz every parameter except for standard fields (fields responsible for Message Type, Seq Number, CheckSum, Body Length etc.).


Key features:
----

- The user can now pass a file containing a list of his own payloads for fuzzing
- Fuzzing specific, user supplied, FIX fields
- Passing multiple parameters for fuzzing
- Handling multiple requests from raw files
- An auto-fuzz functionality was introduced: it generates unusual UTF-8 input and allows the user to control the length and the step of the generated payload

Credits
----

Fixer development was inspired by Fizzer from Gotham Digital Science: https://github.com/GDSSecurity/Fizzer


COPYRIGHT & DISCLAIMER
----

Fixer - Lorenzo Vogelsang, Thanos Polychronis - Copyright (C) 2017 SECFORCE LTD.


This tool is for legal purposes only.


This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.


This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.


You should have received a copy of the GNU General Public License along with this program. If not, see http://www.gnu.org/licenses/.
