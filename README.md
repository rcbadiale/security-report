# security-report

Proccess SAST Security Reports from multiple JSON files into one.

## How to use

First of all, place all your report files into the same folder.

Then it can be run in the CLI as described below.

```
python security_report.py [ARGS]
```

### List of arguments

| long                  | short | description                                                        |
| ----                  | ----  | ----                                                               |
| --help                | -h    | show this help message and exit.                                   |
| --input-files         | -i    | list of input files to be processed.                               |
| --input-path          | -p    | path of input files to be processed.                               |
| --output-file         | -o    | output file where the processed data will be saved.                |
| --ignored-files       | -if   | list of path/files to be ignored (partial name check).             |
| --ignored-identifiers | -ii   | list of identifiers names to be ignored.                           |
| --reasons             | -r    | list of reasons for the filters (only shown on final CLI summary). |

### Example

```
python security_report.py
  -i eslint-sast.json nodejs-sast.json
  -p tmp
  -o tmp/processed.json
  -if static/dist/ node_modules/
  -ii "CWE-79"
  -r "Ignored static compiled files"
```
