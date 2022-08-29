import requests
import datetime
import time
from json.decoder import JSONDecodeError
from datetime import datetime
import json


class CPE:
    """JSON dump class for CPEs

    :var name: CPE URI name
    :vartype name: str

    :var title: The first title result of the CPE.
    :vartype title: str

    :var deprecated: Indicates whether CPE has been deprecated
    :vartype deprecated: bool

    :var cpe23Uri: The CPE name
    :vartype cpe23Uri: str

    :var lastModifiedDate: CPE modification date
    :vartype lastModifiedDate:

    :var titles: Human-readable CPE titles
    :vartype titles: dict

    :var refs: Reference links.
    :vartype refs: dict

    :var deprecatedBy: If deprecated=true, one or more CPE that replace this one
    :vartype deprecatedby: list

    :var vulnerabilities: Optional vulnerabilities associated with this CPE. Must use 'cves = true' argument in searchCPE.
    :vartype vulnerabilities: list
    """

    def __init__(self, dict):
        vars(self).update(dict)

    def __repr__(self):
        return str(self.__dict__)

    def __len__(self):
        return len(vars(self))

    def __iter__(self):
        yield 5
        yield from list(self.__dict__.keys())

    def getvars(self):
        self.title = self.titles[0].title
        self.name = self.cpe23Uri


class CVE:
    """JSON dump class for CVEs

    :var cve: CVE ID, description, reference links, CWE.
    :vartype cve: dict

    :var configurations: CPE applicability statements and optional CPE names.
    :vartype  configurations: dict

    :var impact: CVSS severity scores
    :vartype impact: dict

    :var publishedDate: CVE publication date
    :vartype publishedDate: ISO 8601 date/time format including time zone.

    :var lastModifiedDate: CVE modified date
    :vartype lastModifiedDate: ISO 8601 date/time format including time zone.

    :var id: CVE ID
    :vartype id: str

    :var cwe: Common Weakness Enumeration Specification (CWE)
    :vartype cwe: str

    :var url: Link to additional details on nvd.nist.gov for that CVE.
    :vartype url: str

    :var v3score: List that contains V3 or V2 CVSS score (float 1 - 10) as index 0 and the version that score was taken from as index 1.
    :vartype v3score: list

    :var v2vector: Version two of the CVSS score represented as a vector string, a compressed textual representation of the values used to derive the score.
    :vartype v2vector: str

    :var v3vector: Version three of the CVSS score represented as a vector string.
    :vartype v3vector: str

    :var v2severity: LOW, MEDIUM, HIGH (Critical is only available for v3).
    :vartype v2severity: str

    :var v3severity: LOW, MEDIUM, HIGH, CRITICAL.
    :vartype v3severity: str

    :var v2exploitability: Reflects the ease and technical means by which the vulnerability can be exploited.
    :vartype v2exploitability: float

    :var v3exploitability: Reflects the ease and technical means by which the vulnerability can be exploited.
    :vartype v3exploitability: float

    :var v2impactScore: Reflects the direct consequence of a successful exploit.
    :vartype v2impactScore: float

    :var v3impactScore: Reflects the direct consequence of a successful exploit.
    :vartype v3impactScore: float

    :var score: Contains the v3 CVSS score (v2 if v3 isn't available) [score, severity, version]. Where score is an int, severity is a string('LOW','MEDIUM','HIGH','CRITICAL'), and version is a string (V3 or V2).
    :vartype score: list
    """

    def __init__(self, dict):
        vars(self).update(dict)

    def __repr__(self):
        return str(self.__dict__)

    def __len__(self):
        return len(vars(self))

    def __iter__(self):
        yield 5
        yield from list(self.__dict__.keys())

    def getvars(self):

        self.id = self.cve.CVE_data_meta.ID
        """ ID of the CVE """
        self.cwe = self.cve.problemtype.problemtype_data
        self.url = 'https://nvd.nist.gov/vuln/detail/' + self.id

        if hasattr(self.impact, 'baseMetricV3'):
            self.v3score = self.impact.baseMetricV3.cvssV3.baseScore
            self.v3vector = self.impact.baseMetricV3.cvssV3.vectorString
            self.v3severity = self.impact.baseMetricV3.cvssV3.baseSeverity
            self.v3exploitability = self.impact.baseMetricV3.exploitabilityScore
            self.v3impactScore = self.impact.baseMetricV3.impactScore

        if hasattr(self.impact, 'baseMetricV2'):
            self.v2score = self.impact.baseMetricV2.cvssV2.baseScore
            self.v2vector = self.impact.baseMetricV2.cvssV2.vectorString
            self.v2severity = self.impact.baseMetricV2.severity
            self.v2exploitability = self.impact.baseMetricV2.exploitabilityScore
            self.v2impactScore = self.impact.baseMetricV2.impactScore

        # Prefer the base score version to V3, if it isn't available use V2.
        # If no score is present, then set it to None.
        if hasattr(self.impact, 'baseMetricV3'):
            self.score = ['V3', self.impact.baseMetricV3.cvssV3.baseScore, self.impact.baseMetricV3.cvssV3.baseSeverity]
        elif hasattr(self.impact, 'baseMetricV2'):
            self.score = ['V2', self.impact.baseMetricV2.cvssV2.baseScore, self.impact.baseMetricV2.severity]
        else:
            self.score = [None, None, None]


def __convert(product, CVEID):
    """Convert the JSON response to a referenceable object."""
    if product == 'cve':
        vuln = json.loads(json.dumps(CVEID), object_hook=CVE)
        vuln.getvars()
        return vuln
    else:
        cpeEntry = json.loads(json.dumps(CVEID), object_hook=CPE)
        return cpeEntry


def __get(product, parameters, limit, key, verbose):
    """Calculate required pages for multiple requests, send the GET request with the search criteria, return list of CVEs or CPEs objects."""

    # NIST 6 second rate limit recommendation on requests without API key - https://nvd.nist.gov/developers
    # Get a key, its easy.
    if key:
        delay = 0.6
    else:
        delay = 6

        # Get the default 20 items to see the totalResults and determine pages required.
    if product == 'cve':
        link = 'https://services.nvd.nist.gov/rest/json/cves/1.0?'
    elif product == 'cpe':
        link = 'https://services.nvd.nist.gov/rest/json/cpes/1.0?'
    else:
        raise ValueError('Unknown Product')

    if verbose:
        print('Filter:\n' + link)
        print(parameters)

    raw = requests.get(link, params=parameters, timeout=10)

    try:  # Try to convert the request to JSON. If it is not JSON, then print the response and exit.
        raw = raw.json()
        if 'message' in raw:
            raise LookupError(raw['message'])
    except JSONDecodeError:
        print('Invalid search criteria syntax: ' + str(raw))
        print('Attempted search criteria: ' + parameters)
        exit()

    time.sleep(delay)
    totalResults = raw['totalResults']

    # If a limit is in the search criteria or the total number of results are less than or equal to the default 20 that were just requested, return and don't request anymore.
    if limit or totalResults <= 20:
        return raw

    # If the total results is less than the API limit (Should be 5k but tests shows me 2k), just grab all the results at once.
    elif totalResults > 20 and totalResults < 2000:
        parameters['resultsPerPage'] = str(totalResults)
        raw = requests.get(link, params=parameters, timeout=30).json()
        return raw

    # If the results is more than the API limit, figure out how many pages there are and calculate the number of requests.
    # Send a request starting at startIndex = 0, then get the next page and ask for 2000 more results at the 2000th index result until all results have been grabbed.
    # Add each ['CVE_Items'] list from each page to the end of the first request. Effectively creates one data point.
    elif totalResults > 2000:
        pages = (totalResults // 2000) + 1
        startIndex = 0
        rawTemp = []
        if product == 'cve':
            for eachPage in range(pages):
                parameters['resultsPerPage'] = '2000'
                parameters['startIndex'] = str(startIndex)
                time.sleep(delay)
                getData = requests.get(link, params=parameters, timeout=10).json()['result']['CVE_Items']
                for eachCVE in getData:
                    rawTemp.append(eachCVE.copy())
                startIndex += 2000
            raw['result']['CVE_Items'] = rawTemp
            return raw
        elif 'cpe':
            for eachPage in range(pages):
                parameters['resultsPerPage'] = '2000'
                parameters['startIndex'] = str(startIndex)
                time.sleep(delay)
                getData = requests.get(link, params=parameters, timeout=10).json()['result']['cpes']
                for eachCPE in getData:
                    rawTemp.append(eachCPE.copy())
                startIndex += 2000
            raw['result']['cpes'] = rawTemp
            return raw


def searchCPE(modStartDate=False,
              modEndDate=False,
              includeDeprecated=False,
              keyword=False,
              cpeMatchString=False,
              cves=False,
              limit=False,
              key=False,
              verbose=False):
    """Build and send GET request then return list of objects containing a collection of CPEs.

    :param modStartDate: CPE modification start date. Maximum 120 day range. A start and end date is required. All times are in UTC 00:00.

        A datetime object or string can be passed as a date. NVDLib will automatically parse the datetime object into the correct format.

        String Example: '2020-06-28 00:00'
    :type modStartDate: str/datetime obj

    :param modEndDate: CPE modification end date
    :type modEndDate: str/datetime obj
        Example: '2020-06-28 00:00'

    :param includeDeprecated: Include deprecated CPE names that have been replaced.
    :type includeDeprecated: Bool True

    :param keyword: Free text keyword search.
    :type keyword: str

    :param cpeMatchString: CPE match string search.
    :type cpeMatchString: str

    :param cves: Return vulnerabilities.

        **Warning**: This parameter may incur large amounts of results causing delays.
    :type cves: bool True

    :param limit: Limits the number of results of the search.
    :type limit: int

    :param key: NVD API Key. Allows for a request every 0.6 seconds instead of 6 seconds.
    :type key: str

    :param verbose: Prints the URL request for debugging purposes.
    :type verbose: bool
    """

    def __buildCPECall(
            modStartDate,
            modEndDate,
            includeDeprecated,
            keyword,
            cpeMatchString,
            cves,
            limit,
            key):

        parameters = {}
        if modStartDate:
            if isinstance(modStartDate, datetime):
                date = modStartDate.replace(microsecond=0).isoformat() + ':000 UTC-00:00'
            elif isinstance(modStartDate, str):
                date = str(datetime.strptime(modStartDate, '%Y-%m-%d %H:%M').isoformat()) + ':000 UTC-00:00'
            else:
                raise TypeError('Invalid date syntax: ' + modStartDate)
            parameters['modStartDate'] = date

        if modEndDate:
            if isinstance(modEndDate, datetime):
                date = modEndDate.replace(microsecond=0).isoformat() + ':000 UTC-00:00'
            elif isinstance(modEndDate, str):
                date = str(datetime.strptime(modEndDate, '%Y-%m-%d %H:%M').isoformat()) + ':000 UTC-00:00'
            else:
                raise TypeError('Invalid date syntax: ' + modEndDate)
            parameters['modEndDate'] = date

        if includeDeprecated:
            parameters['includeDeprecated'] = True

        if keyword:
            parameters['keyword'] = keyword

        if cpeMatchString:
            parameters['cpeMatchString'] = cpeMatchString

        if cves:
            if cves == True:
                cves = 'addOns=cves'
                parameters['addOns'] = 'cves'
            else:
                raise TypeError("cves parameter can only be boolean True.")

        if limit:
            if limit > 2000 or limit < 1:
                raise ValueError('Limit parameter must be between 1 and 2000')
            parameters['resultsPerPage'] = limit

        if key:
            parameters['apiKey'] = key

        return parameters

    # Build the URL for the request
    parameters = __buildCPECall(
        modStartDate,
        modEndDate,
        includeDeprecated,
        keyword,
        cpeMatchString,
        cves,
        limit,
        key)

    # Send the GET request for the JSON and convert to dictionary
    raw = __get('cpe', parameters, limit, key, verbose)

    cpes = []
    # Generates the CVEs into objects for easy referencing and appends them to self.cves
    for eachCPE in raw['result']['cpes']:
        cpe = __convert('cpe', eachCPE)
        cpe.getvars()  # Generates cpe.title and cpe.name
        cpes.append(cpe)
    return cpes


def getCVE(CVEID, cpe_dict=False, key=False, verbose=False):
    """Build and send GET request for a single CVE then return object containing CVE attributes.

    :param CVEID: String of the CVE ID of the vulnerability to retrieve more details.
    :type CVEID: str

    :param cpe_dict: Set this value to true to control whether matching CPE names from the Official Dictionary are included in the response.
    :type cpe_dict: Bool True

    :param key: NVD API Key. Allows for a request every 0.6 seconds instead of 6 seconds.
    :type key: str

    :param verbose: Prints the URL request for debugging purposes.
    :type verbose: bool

    """

    def __get(CVEID, cpe_dict, key, verbose):
        searchCriteria = 'https://services.nvd.nist.gov/rest/json/cve/1.0/' + CVEID + '?'
        parameters = {'addOns': None}

        if cpe_dict == True:
            parameters['addOns'] = 'dictionaryCpes'
        elif type(cpe_dict) != bool:
            raise TypeError("cpe_dict parameter must be boolean True or False.")

        if key:  # add the api key to the request
            if type(key) == str:
                parameters['apiKey'] = key
            else:
                raise TypeError("key parameter must be string.")

        if verbose:
            print('Filter:\n' + searchCriteria)
            print(parameters)

        raw = requests.get(searchCriteria, parameters)

        try:
            raw = raw.json()
            if 'message' in raw:  # If no results were found raise error with the message provided from the API
                raise LookupError(raw['message'])

        except JSONDecodeError:
            print('Invalid CVE: ' + str(raw))
            print('Attempted search for CVE ID : ' + CVEID)
            exit()

        # NIST 6 second rate limit recommendation on requests without API key - https://nvd.nist.gov/developers
        # Get a key, its easy.
        if key:
            delay = 0.6
        else:
            delay = 6
        time.sleep(delay)

        return raw

    raw = __get(CVEID, cpe_dict, key, verbose)
    return __convert('cve', raw['result']['CVE_Items'][0])


def searchCVE(
        keyword=False,
        pubStartDate=False,
        pubEndDate=False,
        modStartDate=False,
        modEndDate=False,
        includeMatchStringChange=False,
        exactMatch=False,
        cvssV2Severity=False,
        cvssV3Severity=False,
        cvssV2Metrics=False,
        cvssV3Metrics=False,
        cpeMatchString=False,
        cpeName=False,
        cpe_dict=False,
        cweId=False,
        limit=False,
        key=False,
        verbose=False):
    """Build and send GET request then return list of objects containing a collection of CVEs.

    :param pubStartDate: The pubStartDate and pubEndDate parameters specify the set of CVE that were added to NVD (published) during the period.

        Maximum 120 day range. A start and end date is required. All times are in UTC 00:00.

        A datetime object or string can be passed as a date. NVDLib will automatically parse the datetime object into the correct format.

        String Example: '2020-06-28 00:00'
    :type pubStartDate: str/datetime obj


    :param pubEndDate: Publish end date. Can be used to get all vulnerabilities published up to a specific date and time. All times are in UTC 00:00. A start and end date is required.
    :type pubEndDate: str/datetime obj

    :param modStartDate: The modStartDate and modEndDate parameters specify CVE that were subsequently modified. All times are in UTC 00:00. A start and end date is required.
    :type modStartDate: str/datetime obj

    :param modEndDate: Modifified end date. Can be used to get all vulnerabilities modfied up to a specific date and time. All times are in UTC 00:00. A start and end date is required.
    :type modEndDate: str/datetime obj

    :param includeMatchStringChange: Retrieve vulnerabilities where CPE names changed during the time period. This returns
        vulnerabilities where either the vulnerabilities or the associated product names were modified.
    :type includeMatchStringChange: bool True

    :param keyword: Word or phrase to search the vulnerability description or reference links.
    :type keyword: str

    :param exactMatch: If the keyword is a phrase, i.e., contains more than one term, then the isExactMatch parameter may be
        used to influence the response. Use exactMatch to retrieve records matching the exact phrase.
        Otherwise, the results contain any record having any of the terms.
    :type exactMatch: bool True

    :param cvssV2Severity: Find vulnerabilities having a 'LOW', 'MEDIUM', or 'HIGH' version 2 score.
    :type cvssV2Severity: str

    :param cvssV3Severity: -- Find vulnerabilities having a 'LOW', 'MEDIUM', 'HIGH', or 'CRITICAL' version 3 score.
    :type cvssV3Severity: str

    :param cvssV2Metrics / cvssV3Metrics: -- If your application supports CVSS vector strings, use the cvssV2Metric or cvssV3Metrics parameter to
        find vulnerabilities having those score metrics. Partial vector strings are supported.
    :type cvssV2Metrics: str

    :param cpeMatchString: -- Use cpeMatchString when you want a broader search against the applicability statements attached to the Vulnerabilities
        (e.x. find all vulnerabilities attached to a specific product).
    :type cpeMatchString: str

    :param cpeName: -- Use cpeName when you know what CPE you want to compare against the applicability statements
        attached to the vulnerability (i.e. find the vulnerabilities attached to that CPE).
    :type cpeName: str

    :param cpe_dict: -- Set this value to true to control whether matching CPE from the Official Dictionary for each CVE are included in the response.

        **Warning:** If your search contains many results, the response will be very large as it will contain every CPE that a vulnerability has, thus resulting in delays.
    :type cpe_dict: bool True

    :param limit: -- Custom argument to limit the number of results of the search. Allowed any number between 1 and 2000.
    :type limit: int

    :param key: NVD API Key. Allows for a request every 0.6 seconds instead of 6 seconds.
    :type key: str

    :param verbose: Prints the URL request for debugging purposes.
    :type verbose: bool
    """

    def __buildCVECall(
            keyword,
            pubStartDate,
            pubEndDate,
            modStartDate,
            modEndDate,
            includeMatchStringChange,
            exactMatch,
            cvssV2Severity,
            cvssV3Severity,
            cvssV2Metrics,
            cvssV3Metrics,
            cpeMatchString,
            cpeName,
            cpe_dict,
            cweId,
            limit,
            key):

        parameters = {}

        if keyword:
            parameters['keyword'] = keyword

        if pubStartDate:
            if isinstance(pubStartDate, datetime):
                date = pubStartDate.replace(microsecond=0).isoformat() + ':000 UTC-00:00'
            elif isinstance(pubStartDate, str):
                date = str(datetime.strptime(pubStartDate, '%Y-%m-%d %H:%M').isoformat()) + ':000 UTC-00:00'
            else:
                raise TypeError('Invalid date syntax: ' + pubEndDate)
            parameters['pubStartDate'] = date

        if pubEndDate:
            if isinstance(pubEndDate, datetime):
                date = pubEndDate.replace(microsecond=0).isoformat() + ':000 UTC-00:00'
            elif isinstance(pubEndDate, str):
                date = str(datetime.strptime(pubEndDate, '%Y-%m-%d %H:%M').isoformat()) + ':000 UTC-00:00'
            else:
                raise TypeError('Invalid date syntax: ' + pubEndDate)
            parameters['pubEndDate'] = date

        if modStartDate:
            if isinstance(modStartDate, datetime):
                date = modStartDate.replace(microsecond=0).isoformat() + ':000 UTC-00:00'
            elif isinstance(modStartDate, str):
                date = str(datetime.strptime(modStartDate, '%Y-%m-%d %H:%M').isoformat()) + ':000 UTC-00:00'
            else:
                raise TypeError('Invalid date syntax: ' + modStartDate)
            parameters['modStartDate'] = date

        if modEndDate:
            if isinstance(modEndDate, datetime):
                date = modEndDate.replace(microsecond=0).isoformat() + ':000 UTC-00:00'
            elif isinstance(modEndDate, str):
                date = str(datetime.strptime(modEndDate, '%Y-%m-%d %H:%M').isoformat()) + ':000 UTC-00:00'
            else:
                raise TypeError('Invalid date syntax: ' + modEndDate)
            parameters['modEndDate'] = date

        if includeMatchStringChange:
            if includeMatchStringChange == True:
                parameters['includeMatchStringChange'] = True
            else:
                raise TypeError("includeMatchStringChange parameter can only be boolean True.")

        if exactMatch:
            if exactMatch == True:
                parameters['exactMatch'] = True
            else:
                raise TypeError("exactMatch parameter can only be boolean True.")

        if cvssV2Severity:
            cvssV2Severity = cvssV2Severity.upper()
            if cvssV2Severity in ['LOW', 'MEDIUM', 'HIGH']:
                parameters['cvssV2Severity'] = cvssV2Severity
            else:
                raise ValueError("cvssV2Severity parameter can only be assigned LOW, MEDIUM, or HIGH value.")

        if cvssV3Severity:
            cvssV3Severity = cvssV3Severity.upper()
            if cvssV3Severity in ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']:
                parameters['cvssV3Severity'] = cvssV3Severity
            else:
                raise ValueError("cvssV3Severity parameter can only be assigned LOW, MEDIUM, HIGH, or CRITICAL value.")

        if cvssV2Metrics:
            parameters['cvssV2Metrics'] = cvssV2Metrics

        if cvssV3Metrics:
            parameters['cvssV3Metrics'] = cvssV3Metrics

        if cpeMatchString:
            parameters['cpeMatchString'] = cpeMatchString

        if cpeName:
            parameters['cpeName'] = cpeName

        if cpe_dict:
            if cpe_dict == True:
                parameters['addOns'] = 'dictionaryCpes'
            else:
                raise TypeError("cpe_dict parameter can only be boolean True.")

        if cweId:
            parameters['cweId'] = cweId

        if limit:
            if limit > 2000 or limit < 1:
                raise ValueError('Limit parameter must be between 1 and 2000')
            parameters['resultsPerPage'] = str(limit)

        if key:
            parameters['apiKey'] = key

        return parameters

    parameters = __buildCVECall(keyword,
                                pubStartDate,
                                pubEndDate,
                                modStartDate,
                                modEndDate,
                                includeMatchStringChange,
                                exactMatch,
                                cvssV2Severity,
                                cvssV3Severity,
                                cvssV2Metrics,
                                cvssV3Metrics,
                                cpeMatchString,
                                cpeName,
                                cpe_dict,
                                cweId,
                                limit,
                                key)

    # raw is the raw dictionary response.
    raw = __get('cve', parameters, limit, key, verbose)
    cves = []
    # Generates the CVEs into objects for easy access and appends them to self.cves
    for eachCVE in raw['result']['CVE_Items']:
        cves.append(__convert('cve', eachCVE))
    return cves
