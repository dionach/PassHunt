PassHunt
========

##Introduction

PassHunt searches drives for documents that contain passwords or any other regular expression. It's designed to be a simple, standalone tool that can be run from a USB stick.

## Build

PassHunt is a Python script that can be easily converted to a standalone Windows executable using PyInstaller.

panhunt.py requires:

	- Python 2.7
	- Colorama (https://pypi.python.org/pypi/colorama)
	- Progressbar (https://pypi.python.org/pypi/progressbar)
	- PyInstaller (https://pypi.python.org/pypi/PyInstaller)

To create passhunt.exe as a standalone executable with an icon run:

```
pyinstaller.exe passhunt.py -F -i dionach.ico
```	

##Usage

```
usage: passhunt [-h] [-s SEARCH] [-x EXCLUDE] [-t TEXTFILES] [-z ZIPFILES] [-e SPECIALFILES] [-m MAILFILES] [-l OTHERFILES] [-o OUTFILE]

PassHunt v0.9: search directories and sub directories for documents containing passwords.

optional arguments:
  -h, --help       show this help message and exit
  -s SEARCH        base directory to search in (default: C:\)
  -x EXCLUDE       directories to exclude from the search (default:
                   C:\Windows,C:\Program Files,C:\Program Files (x86))
  -t TEXTFILES     text file extensions to search (default: .doc,.xls,.xml,.tx
                   t,.csv,.config,.ini,.vbs,.vbscript,.bat,.pl,.asp,.sh,.php,.
                   inc,.conf,.inf,.reg)
  -z ZIPFILES      zip file extensions to search (default: .docx,.xlsx,.zip)
  -e SPECIALFILES  special file extensions to search (default: .msg)
  -m MAILFILES     email file extensions to search (default: .pst)
  -l OTHERFILES    other file extensions to list (default:
                   .ost,.accdb,.mdb,.kdb,.asc,.cer,.crt,.pem,.der)
  -o OUTFILE       HTML output file name for report (default:
                   passhunt_2014-07-11-093500.html)
```

Simply running it with no arguments will search the C:\ drive for documents containing passwords, and output to an HTML report file.


## Function

The script uses a regular expression which defaults to "password" to look for passwords in document files, including text files, PST files and MSG files. Zip files are recursed to look for document files. The script will list but does not yet search Access databases.
