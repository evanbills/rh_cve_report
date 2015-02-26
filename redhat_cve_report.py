#!/usr/bin/env python

# Author: Evan Bills
# Description: This utility makes calls to the Red Hat CVE database to retrieve the CVE details.
# Usage: This script takes a list of CVEs as input and produces a report containing details, statements, and links to any related errata.
#        The input file should be plain text with one CVE per line. e.g.:
#
#        CVE-2015-0409
#        CVE-2015-0411
#        CVE-2015-0432
#        ...
#
# Syntax: redhat_cve_report.py <CVE_List>


# Required modules. 
# If python complains about these, install with 'pip install requests'  or 'pip install bs4'
import requests
import bs4
import csv
import sys


CVEURLBase = "https://access.redhat.com/security/cve/"
filename = sys.argv[-1]

with open(filename, 'rb') as f:
	reader = csv.reader(f)
	CVEList = list(reader)
	for row in CVEList:
		CVENum = "".join(row)
		CVEURL = 'https://access.redhat.com/security/cve/' + CVENum
		response = requests.get(CVEURL)
		soup = bs4.BeautifulSoup(response.text)
		ImpactStr = soup.select('div.cve td') [0].get_text()
		DatePublicStr = soup.select('div.cve td') [1].get_text()
		DetailsUGH = soup.select('div.cve blockquote') [0].get_text()
		DetailsStr = DetailsUGH.strip()
		if soup.find_all('h2',text='Statement'):
			StatementStr = soup.find(text="Statement").findNext('p').contents[0]
		else:
			StatementStr = 'N/A'
		print "---------------------------------------------------------------------------------------------------"
		print "Pulling details for " + CVENum
		print "CVE URL: " + CVEURLBase + "/" + CVENum
		print "Impact: " + ImpactStr
		print "Public: " + DatePublicStr
		print "Statement: " + StatementStr
		print "Details: " + DetailsStr
		print "Errata List: "

		for tr in soup('table')[2].find_all('tr')[1:]:
			col = tr.findAll('td')
			platform = col[0].string
			errata = col[1].string
			releasedate = col[2].string
			record = (platform,errata,releasedate)
			print " | ".join(record)
