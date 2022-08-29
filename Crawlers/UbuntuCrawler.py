import requests
from bs4 import BeautifulSoup
from datetime import datetime
import Viradb
from . import Nvdapi


class UbuntuCrawler():
    db = Viradb.Viradb()
    #
    Score = db.Score
    Docs_Content = db.Docs_Content
    CWE = db.CWE
    Brand = db.Brand
    Product = db.Product

    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.102 Safari/537.36'}
    page = None
    soup = None
    list_score_desc = {'High': 7.8, 'Low': 3.3, 'Medium': 6, 'Critical': 9.8, 'Negligible': None, 'Unknown': None}

    def getcve(self, pages=[0, 20, 40]):
        for page in pages:
            url = "https://ubuntu.com/security/cves?offset={}".format(page)
            try:
                page = requests.get(url, headers=self.headers, stream=True)
                soup = BeautifulSoup(page.content, "html.parser")
                cvetablecellid = soup.find_all('td', attrs={'class': 'cve-table-cell-id'})
                if len(cvetablecellid) < 0:
                    return print('can not find any cve !', 'err in page : {} !'.format(url))
            except:
                return print(page.status_code, 'err in page : {} !'.format(url))

            for id in cvetablecellid:
                cveid = id.find('a').text
                self.get_one(cveid)

    # get and update one CVE
    def get_one(self, cve_id):
        print(cve_id, 'UbuntuCrawler start')
        cve_sh = self.Docs_Content.find_one({'cve_id': cve_id})
        try:
            brandid = (self.Brand.find_one({'brand_id': 'linux'}))['_id']
            poductid = (self.Product.find_one({'brand_id': brandid, 'product_id': 'ubuntu'}))['_id']
        except:
            brandid = self.Brand.insert_one({'brand_id': 'linux'}).inserted_id
            poductid = self.Product.insert_one({'brand_id': brandid, 'product_id': 'ubuntu'}).inserted_id
        if cve_sh == None:
            url = 'https://ubuntu.com/security/{}'.format(cve_id)
            cve_url = {'ubuntu': url}
            cvepage = requests.get(url, headers=self.headers)
            soup = BeautifulSoup(cvepage.content, features="lxml")
            try:
                section = soup.find('section', attrs={'class': 'p-strip'})
            except:
                print('err in page : {} !'.format(url))

            try:
                NVDobj = Nvdapi.getCVE(cve_id)
                description_data = NVDobj.cve.description.description_data[0]
                discriptons = description_data.value
                cve_url = cve_url | {'nvd': "https://nvd.nist.gov/vuln/detail/" + cve_id}
            except:
                pass
                discriptons = section.find('div', attrs={'class': 'row'}).find('div', attrs={'class': 'col-9'}).find(
                    'p').findNext().findNext().text

            published_date = section.find('div', attrs={'class': 'row'}).find('div', attrs={'class': 'col-9'}).find(
                'p').find('strong').text
            try:
                score_desc = section.find('h4', attrs={
                    'class': 'p-heading-icon__title u-no-margin--bottom'}).text.replace(' ', '').replace('\n', '')
                try:
                    score_status = section.find('div', attrs={'class': 'row'}).find('div', attrs={
                        'class': 'cve-status-box u-no-margin--bottom'}).find_next_sibling('p').text

                    if score_status.find('CVSS 3') >= 0:
                        version = 'V3'
                    elif score_status.find('CVSS 2') >= 0:
                        version = 'V2'
                    else:
                        version = None

                    if score_status.find('base score') >= 0:
                        inndx = score_status.index(':')
                        score = float(score_status[inndx + 1:].replace(' ', ''))
                    else:
                        score = None
                except:
                    score = None
                    version = None
            except:
                score_desc = None

            # insert data
            # Insert to Docs_Content
            # hyperlinks
            links = section.find('div', attrs={'class': 'row'}).find_next_sibling().find_next_sibling().find(
                'ul').find_all('a')
            if len(links) > 0:
                hyperlinks = []
                for item in links:
                    link = item.get_attribute_list('href')
                    hyperlinks.append(link[0])
            else:
                hyperlinks = None
            Insertdata = {
                'cve_id': cve_id,
                'year': datetime.strptime(published_date, '%d %B %Y').year,
                'month': datetime.strptime(published_date, '%d %B %Y').month,
                'cve_url': cve_url,
                'published_date': datetime.strptime(published_date, '%d %B %Y').strftime('%Y-%m-%dT00:00Z'),
                'modified_date': datetime.now(),
                'source': 'ubuntu',
                'discriptons': discriptons,
                'hyperlinks': hyperlinks,
                'cwe_id': None,
                'product_id': poductid,
            }
            self.Docs_Content.insert_one(Insertdata)
            # Insert to Score
            if score == None:
                score = self.list_score_desc[score_desc]
            Insertdata = {
                'cve_id': cve_id,
                'titel': None,
                'source': 'ubuntu',
                'score': score,
                'score_desc': score_desc,
                'vector': None,
                'version': version,
                'accessvector': None
            }
            self.Score.insert_one(Insertdata)

        # If In DB
        else:
            # update Doct
            print(cve_id)
            url = 'https://ubuntu.com/security/{}'.format(cve_id)
            cve_url = cve_sh['cve_url']
            if cve_url == None:
                cve_url = {'ubuntu': url}
            else:
                cve_url = cve_url | {'ubuntu': url}
            self.Docs_Content.update_one({'cve_id': cve_id}, {"$set": {'cve_url': cve_url}})
            hyperlinks = self.Docs_Content.find_one({'cve_id': cve_id})['hyperlinks']
            if hyperlinks == None:
                hyperlinks = []
            url = 'https://ubuntu.com/security/{}'.format(cve_id)
            cvepage = requests.get(url, headers=self.headers, stream=True)
            soup = BeautifulSoup(cvepage.content,"lxml")
            section = soup.find('section', attrs={'class': 'p-strip'})
            links = section.find('div', attrs={'class': 'row'}).find_next_sibling().find_next_sibling().find(
                'ul').find_all('a')
            if len(links) > 0:
                for item in links:
                    link = item.get_attribute_list('href')
                    hyperlinks.append(link[0])
                hyperlinks = [i for i in set(hyperlinks)]
                myquery = {"cve_id": cve_id}
                newvalues = {"$set": {"hyperlinks": hyperlinks}}
                self.Docs_Content.update_one(myquery, newvalues)

            # Score
            try:
                score_desc = section.find('h4', attrs={
                    'class': 'p-heading-icon__title u-no-margin--bottom'}).text.replace(' ', '').replace('\n', '')
                try:
                    score_status = section.find('div', attrs={'class': 'row'}).find('div', attrs={
                        'class': 'cve-status-box u-no-margin--bottom'}).find_next_sibling('p').text

                    if score_status.find('CVSS 3') >= 0:
                        version = 'V3'
                    elif score_status.find('CVSS 2') >= 0:
                        version = 'V2'
                    else:
                        version = None

                    if score_status.find('base score') >= 0:
                        inndx = score_status.index(':')
                        score = float(score_status[inndx + 1:].replace(' ', ''))
                    else:
                        score = None
                except:
                    score = None
                    version = None
            except:
                score_desc = None

            if score == None:
                score = self.list_score_desc[score_desc]

            if self.Score.find_one({'source': 'ubuntu', 'cve_id': cve_id}) == None:
                Insertdata = {
                    'cve_id': cve_id,
                    'titel': None,
                    'source': 'ubuntu',
                    'score': score,
                    'score_desc': score_desc,
                    'vector': None,
                    'version': version,
                    'accessvector': None
                }
                self.Score.insert_one(Insertdata)
