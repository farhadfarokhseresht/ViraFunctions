from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from webdriver_manager.chrome import ChromeDriverManager
import NvdCrawler
import time
from datetime import datetime
import Viradb


class F5Crawler():
    db = Viradb.Viradb()
    #
    Score = db.Score
    Docs_Content = db.Docs_Content
    CWE = db.CWE
    Brand = db.Brand
    Product = db.Product
    chromedriver = Service(ChromeDriverManager().install())
    nvdcheck = NvdCrawler.NvdCrawler()

    def score_desc(score):
        if 0.1 <= score <= 3.9:
            return 'Low'
        elif 4 <= score <= 6.9:
            return 'Medium'
        elif 7 <= score <= 8.9:
            return 'High'
        elif 9 <= score <= 10:
            return 'Critical'
        else:
            return None

    page = None
    soup = None
    chromedriver = Service(ChromeDriverManager().install())

    def popup(self, driver):
        container = driver.find_element(by=By.CLASS_NAME, value='truste-consent-container')
        container.find_element(by=By.ID, value='truste-consent-button').click()

    def getcve(self):
        url = 'https://support.f5.com/csp/article/K50974556'
        headers = {
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.102 Safari/537.36'}
        print('F5 Network Start')
        CVE_list = {}
        f5_driver = webdriver.Chrome(service=self.chromedriver)
        f5_driver.minimize_window()
        try:
            f5_driver.get(url)
            self.popup(f5_driver)
        except:
            print('can not get F5 url')
        time.sleep(6)
        try:
            f5_driver.find_element(by=By.XPATH, value='/html/body/div[6]/div/div[2]').click()
        except:
            pass
        # get cve links
        uls = f5_driver.find_elements(by=By.TAG_NAME, value="ul")
        cvelinks = []
        for ul in uls:
            lis = ul.find_elements(by=By.TAG_NAME, value='li')
            for li in lis:
                try:
                    link = li.find_element(by=By.TAG_NAME, value='a')
                    if (link.text).find('CVE-') >= 0:
                        cvelinks.append(link.get_attribute('href'))
                except:
                    pass
        # go to cve page
        for cvelink in cvelinks[0:3]:
            f5_driver.get(cvelink)
            try:
                self.popup(f5_driver)
            except:
                pass
            time.sleep(6)
            try:
                f5_driver.find_element(by=By.XPATH, value='/html/body/div[6]/div/div[2]').click()
            except:
                pass
            cveid = f5_driver.find_element(by=By.XPATH, value='//*[@id="articleContainer"]/div[1]/div/h2')
            cveid = cveid.text
            cveid = cveid[cveid.index('CVE-'):]
            dates = f5_driver.find_element(by=By.XPATH,
                                           value='//*[@id="articleContainer"]/csp-article-version/div/div/section/div/div[1]')
            dates = dates.find_element(by=By.TAG_NAME, value='p')
            dates = (dates.text).split('\n')
            PublicationDate = dates[0]
            PublicationDate = PublicationDate[27:]
            PublicationDate = PublicationDate.replace(',', '')
            PublicationDate = time.strptime(PublicationDate, '%b %d %Y')
            UpdatedDate = datetime.now()
            discriptons = (f5_driver.find_element(by=By.XPATH,
                                                  value='//*[@id="articleContainer"]/div[2]/div/div[2]/div/p[1]/span')).text
            ptable = f5_driver.find_element(by=By.XPATH,
                                            value='//*[@id="articleContainer"]/div[2]/div/div[3]/div/div/table')
            trs = ptable.find_elements(by=By.TAG_NAME, value='tr')
            cvssrow = trs[1]
            cvssrow = cvssrow.find_elements(by=By.TAG_NAME, value='td')
            Severity = (cvssrow[4]).text
            try:
                score = cvssrow[5].text
                score = score[:2]
                score = float(score)
            except:
                score = None
            product_list = []
            for tr in trs[1:]:
                tds = tr.find_elements(by=By.TAG_NAME, value='td')
                if len(tds) >= 6:
                    product = (tds[0]).text
                    product_list.append(product)
            CVE_list[cveid] = [cvelink, discriptons, PublicationDate, UpdatedDate, Severity, score, product_list]
        f5_driver.close()

        if len(CVE_list.keys()) > 0:
            for cve_id in CVE_list.keys():
                cve_info = CVE_list[cve_id]
                try:
                    self.nvdcheck.update_one(cve_id)
                except:
                    pass
                cve_sh = self.Docs_Content.find_one({'cve_id': cve_id})
                if cve_sh != None:
                    cve_url = cve_sh['cve_url']
                    if cve_url == None:
                        cve_url = {'f5': cve_info[0]}
                    else:
                        cve_url = cve_url | {'f5': cve_info[0]}
                    self.Docs_Content.update_one({'cve_id': cve_id}, {"$set": {'cve_url': cve_url}})
                    # product_id
                    product_id_list = []
                    brandid = self.Brand.find_one({'brand_id': 'f5'})
                    if brandid != None:
                        brandid = brandid['_id']
                    else:
                        brandid = self.Brand.insert_one({'brand_id': 'f5'}).inserted_id
                    try:
                        for prod in cve_info[6]:
                            prod = prod.lower()
                            product_objs = self.Product.find_one({'brand_id': brandid, 'product_id': prod})
                            if product_objs != None:
                                product_id_list.append(product_objs['_id'])
                            else:
                                product_objs = self.Product.insert_one(
                                    {'brand_id': brandid, 'product_id': prod}).inserted_id
                                product_id_list.append(product_objs)
                    except:
                        product_objs = self.Product.insert_one(
                            {'brand_id': brandid, 'product_id': 'f5_other'}).inserted_id
                        product_id_list.append(product_objs)

                    if len(product_id_list) <= 0:
                        product_update = None
                    else:
                        product_id_list = list(set(product_id_list))
                        try:
                            product_update = list(set(cve_sh['product_id'] + product_id_list))
                        except:
                            product_update = product_id_list

                    Docs_Content_Update = {
                        'product_id': product_update,
                        'modified_date': datetime.now(),
                        'cve_url': cve_url,
                    }
                    self.Docs_Content.update_one({'cve_id': cve_id}, {"$set": Docs_Content_Update})
                    # Update score
                    if self.Score.find_one({'cve_id': cve_id, 'source': 'f5'}) == None:
                        Insertdata = {
                            'cve_id': cve_id,
                            'titel': None,
                            'source': 'f5',
                            'score': cve_info[5],
                            'score_desc': cve_info[4],
                            'vector': None,
                            'version': 'V3',
                            'accessvector': None
                        }
                        self.Score.insert_one(Insertdata)
                else:
                    # if not in db

                    # check for brand and product
                    product_id_list = []
                    brandid = self.Brand.find_one({'brand_id': 'f5'})
                    if brandid != None:
                        brandid = brandid['_id']
                    else:
                        brandid = self.Brand.insert_one({'brand_id': 'f5'}).inserted_id
                    try:
                        for prod in cve_info[6]:
                            prod = prod.lower()
                            product_objs = self.Product.find_one({'brand_id': brandid, 'product_id': prod})
                            if product_objs != None:
                                product_id_list.append(product_objs['_id'])
                            else:
                                product_objs = self.Product.insert_one(
                                    {'brand_id': brandid, 'product_id': prod}).inserted_id
                                product_id_list.append(product_objs)
                    except:
                        product_objs = self.Product.insert_one(
                            {'brand_id': brandid, 'product_id': 'f5_other'}).inserted_id
                        product_id_list.append(product_objs)

                    if len(product_id_list) <= 0:
                        product_id_list = None
                    else:
                        product_id_list = list(set(product_id_list))

                    # Insert  to  Docs_Content
                    Insertdata = {
                        'published_date': cve_info[2].strftime('%Y-%m-%dT%H:%MZ'),
                        'modified_date': datetime.now(),
                        'source': 'f5',
                        'cve_id': cve_id,
                        'year': int((cve_info[2]).year),
                        'month': int((cve_info[2]).month),
                        'cve_url': {'f5': cve_info[0]},
                        'discriptons': cve_info[0],
                        'hyperlinks': None,
                        'cwe_id': None,
                        'product_id': product_id_list,
                    }
                    self.Docs_Content.insert_one(Insertdata)
                    # Insert to Score
                    Insertdata = {
                        'cve_id': cve_id,
                        'titel': None,
                        'source': 'f5',
                        'score': cve_info[5],
                        'score_desc': cve_info[4],
                        'vector': None,
                        'version': 'V3',
                        'accessvector': None
                    }
                    self.Score.insert_one(Insertdata)
        print('F5Crawler End successfuly')
