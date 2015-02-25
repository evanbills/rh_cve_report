#!/usr/bin/env python
import requests
import bs4
import csv


CVEURLBase = "https://access.redhat.com/security/cve/"


with open('CVE_List.txt', 'rb') as f:
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
		StatementStr = soup.select('div.cve p') [3].get_text()
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
