import datetime
import requests
from bs4 import BeautifulSoup
from datetime import datetime
import Viradb
from . import NvdCrawler


class FortinetCrawler():
    db = Viradb.Viradb()
    #
    Score = db.Score
    Docs_Content = db.Docs_Content
    CWE = db.CWE
    Brand = db.Brand
    Product = db.Product
    nvdcheck = NvdCrawler.NvdCrawler()
    now = datetime.now()
    month = now.month
    year = now.year
    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.102 Safari/537.36'}

    def getcve(self, month=month, year=year, npage=False):
        if month < 10:
            month = '0' + str(month)
        url = "https://www.fortiguard.com/psirt?date={}-{}".format(month, year)

        if npage != False:
            url = 'https://www.fortiguard.com/psirt?page={}'.format(npage)

        page = requests.get(url, headers=self.headers)
        soup = BeautifulSoup(page.content, features="html.parser")
        articlerows = soup.find_all('div', attrs={'class': 'article row'})
        for article in articlerows:
            cveurl = article.find('div', attrs={'class': 'title'}).find('a')
            cveurl = 'https://www.fortiguard.com' + cveurl.get_attribute_list('href')[0]
            self.get_one_cve(cveurl)

    def get_one_cve(self, url):
        cvepage = requests.get(url, headers=self.headers)
        cvesoup = BeautifulSoup(cvepage.content, features="html.parser")
        section2 = cvesoup.find('div', attrs={'class': 'sidebar-content'}).find_all('tr')
        CVEID = None
        date = None
        Severity = None
        Score = None
        for item in section2:
            try:
                if str(item).find('CVE ID') >= 0:
                    CVEID = item.find_all('td')[1].find('a').text
            except:
                pass

            try:
                if str(item).find('Date') >= 0:
                    date = item.find_all('td')[1].text
                    date = datetime.strptime(date, '%b %d, %Y')
                    date = date.strftime('%Y-%m-%dT%H:%MZ')
            except:
                pass

            try:
                if str(item).find('Severity') >= 0:
                    Severity = item.find_all('td')[1].text
                    Severity = Severity.splitlines()[7]
            except:
                pass

            try:
                if str(item).find('CVSSv') >= 0:
                    Score = item.find_all('td')[1].text
                    Score = float(Score)
            except:
                pass
        forti_product_list = ['fortios', 'fortiweb', 'fortimanager', 'fortianalyzer', 'frtiproxy', 'frtimail',
                              'frtiportal', 'frtisendbox',
                              'forticlientwindows', 'fortiauthenticator', 'fortiap', 'FortiSwitch', 'FortiGate',
                              'FortiWiFi']
        section1 = cvesoup.find('section', attrs={'class': 'ency_content'})
        detailitems = section1.find_all('div', {'class': 'detail-item'})
        title = detailitems[0].find('h2', attrs={'class': 'title'}).text
        discripton = None
        products = None
        for item in detailitems:
            try:
                h3 = item.find('h3')
                if str(h3).find('Summary') >= 0:
                    discripton = item.text
            except:
                pass

            try:
                h3 = item.find('h3')
                if str(h3).find('Description') >= 0:
                    discripton = item.text.replace(' ', '').splitlines()
                    discripton = ' '.join(discripton)
            except:
                pass

            try:
                h3 = item.find('h3')
                if str(h3).find('Affected Products') >= 0:
                    product_txt = item.text
                    product_txt = product_txt.lower()
                    products = []
                    for item in forti_product_list:
                        item = item.lower()
                        if (product_txt.find(item) >= 0) and (item not in products):
                            products.append(item)
            except:
                pass

        cve_sh = self.Docs_Content.find_one({'cve_id': cve_id})
        # Update Doct
        url = 'https://msrc.microsoft.com/update-guide/vulnerability/' + cve_id
        cve_url = cve_sh['cve_url']
        if cve_url == None:
            cve_url = {'microsoft': url}
        else:
            cve_url = cve_url | {'microsoft': url}
        # product_id
        product_id_list = []
        try:
            product_id_list = [i for i in Docs_Content_obj['product_id']]
        except:
            pass

        brandid = self.Brand.find_one({'brand_id': 'microsoft'})
        if brandid != None:
            brandid = brandid['_id']
        else:
            brandid = self.Brand.insert_one({'brand_id': 'microsoft'}).inserted_id

        product_objs = self.Product.find_one({'brand_id': brandid, 'product_id': cveinfo[2]})
        if product_objs != None:
            if product_objs['_id'] not in product_id_list:
                product_id_list.append(product_objs['_id'])
        else:
            product_objs = self.Product.insert_one({'brand_id': brandid, 'product_id': cveinfo[2]}).inserted_id
            if product_objs not in product_id_list:
                product_id_list.append(product_objs)

        if len(product_id_list) <= 0:
            product_id_list = None

        Docs_Content_Update = {
            'product_id': product_id_list,
            'modified_date': datetime.datetime.now(),
            'cve_url': cve_urlو
        }
        self.Docs_Content.update_one({'cve_id': cve_id_ObjectId}, {"$set": Docs_Content_Update})

        # Update score

        if self.Score.find_one({'cve_id': cve_id, 'source': 'microsoft'}) == None:
            Insertdata = {
                'cve_id': cve_id,
                'titel': None,
                'source': 'microsoft',
                'score': float(cveinfo[4]),
                'score_desc': self.score_desc(float(cveinfo[4])),
                'vector': cveinfo[5],
                'version': cveinfo[3],
                'accessvector': None
            }
        self.Score.insert_one(Insertdata)
