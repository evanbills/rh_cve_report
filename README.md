Red Hat CVE Report Generator (python version)

Original Author: Brandon Williams, updated by Evan Bills to use Python
Description: This utility makes calls to the Red Hat CVE database to retrieve the CVE details.
Usage: This script takes a list of CVEs as input and produces a report containing details, statements, and links to any related errata.
       The input file should be plain text with one CVE per line. e.g.:

       CVE-2015-0409
       CVE-2015-0411
       CVE-2015-0432
       ...

Syntax: redhat_cve_report.py <CVE_List> to use as input

CVE_List.txt contains a sample CVE List
CVE_Report.txt contains a sample report

Version 0.1 - February 19, 2015
- Initial version

Version 0.1.1 - February 19, 2015
- Fixed issue where statements weren't being reported correctly
- Fixed issue where strings with "**" were causing directory information to be printed instead of the asterisk characters themselves

Version 0.1.2 - February 23, 2015
- Converted script to use Python's Beautiful Soup and requests 
- If you are missing either of those modules, install with:
		'pip install requests'
				or
		'pip install bs4'  #for Beautiful Soup
