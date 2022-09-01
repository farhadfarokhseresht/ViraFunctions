from datetime import datetime
from selenium import webdriver
from selenium.common.exceptions import TimeoutException
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from webdriver_manager.chrome import ChromeDriverManager
import NvdCrawler, Viradb
import time


class MicrosoftCrawler():
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

    def getcve(self):
        try:
            microsoft_driver = webdriver.Chrome(service=self.chromedriver)
            # microsoft_driver.minimize_window()
            microsoft_driver.get('https://msrc.microsoft.com/update-guide/vulnerability')
            time.sleep(10)
            print(' MicrosoftCrawler Start')
            while True:
                try:
                    loadbutton = microsoft_driver.find_element(by=By.XPATH,
                                                               value='//*[@id="objectObject"]/div/div[2]/div[3]/div[3]/button')
                    loadbutton.click()
                except:
                    break
        except TimeoutException:
            print('too long !')
            microsoft_driver.close()

        table = microsoft_driver.find_element(by=By.XPATH,
                                              value='//*[@id="objectObject"]/div/div[2]/div[3]/div[2]/div/div[2]')
        rows = table.find_elements(by=By.CSS_SELECTOR, value='.ms-List-cell')
        cve_list = []
        for row in rows:
            cve_ids = row.find_elements(by=By.TAG_NAME, value='a')
            for cve_id in cve_ids:
                if (cve_id.text not in cve_list and (cve_id.text).find('CVE') >= 0):
                    cve_list.append(cve_id.text)

        microsoft_cves = {}
        for cve_id in cve_list[0:1]:
            try:
                print('MicrosoftCrawler :', cve_id)
                cveurl = 'https://msrc.microsoft.com/update-guide/vulnerability/' + cve_id
                microsoft_driver.get(cveurl)
                time.sleep(10)
                discriptons = None
                try:
                    discriptons = microsoft_driver.find_element(by=By.XPATH,
                                                                value='//*[@id="title"]/div/div/div/div[1]/div/div[1]/h1')
                    discriptons = discriptons.text
                except:
                    pass
                brand_id = 'microsoft'
                product_id = 'other'
                try:
                    product_id = (microsoft_driver.find_element(by=By.XPATH,
                                                                value='/html/body/div/div/div/div/div/div[4]/div[5]/div/div/div/div/div/div/div[3]/div[2]/div/div[2]/div/div/div/div[2]/div/div/div/div/div/div/div/div/div[2]')).text
                except:
                    pass
                version = None
                score = None
                try:
                    cvss = (microsoft_driver.find_element(by=By.XPATH,
                                                          value='//*[@id="title"]/div/div/div/div[3]/div[1]/div/label')).text
                    version = "V" + cvss[5:6]
                    score = cvss[9:cvss.index('/') - 1]
                except:
                    pass
                published_date = None
                try:
                    published_date = (
                        microsoft_driver.find_element(by=By.XPATH, value='//*[@id="title"]/div/div/div/p[1]')).text
                    published_date = (published_date[published_date.index(':') + 2:]).replace(',', '')
                    published_date = datetime.strptime(published_date, '%b %d %Y')
                    published_date = datetime.strptime(published_date, '%Y-%m-%dT%H:%MZ')
                except:
                    pass
                Vector = None
                try:
                    AttackVector = microsoft_driver.find_element(by=By.XPATH,
                                                                 value='/html/body/div/div/div/div/div/div[4]/div[1]/div/div/div/div/div[3]/div[3]/div/div/div[2]/div/div/div/div/div[1]/div/div/div[2]/div/div/div[1]/div/div/div[2]/details/summary').text
                    AttackComplexity = microsoft_driver.find_element(by=By.XPATH,
                                                                     value='/html/body/div/div/div/div/div/div[4]/div[1]/div/div/div/div/div[3]/div[3]/div/div/div[2]/div/div/div/div/div[1]/div/div/div[2]/div/div/div[2]/div/div/div[2]/details/summary').text
                    PrivilegesRequired = microsoft_driver.find_element(by=By.XPATH,
                                                                       value='/html/body/div/div/div/div/div/div[4]/div[1]/div/div/div/div/div[3]/div[3]/div/div/div[2]/div/div/div/div/div[1]/div/div/div[2]/div/div/div[3]/div/div/div[2]/details/summary').text
                    UserInteraction = microsoft_driver.find_element(by=By.XPATH,
                                                                    value='/html/body/div/div/div/div/div/div[4]/div[1]/div/div/div/div/div[3]/div[3]/div/div/div[2]/div/div/div/div/div[1]/div/div/div[2]/div/div/div[4]/div/div/div[2]/details/summary').text
                    Scope = microsoft_driver.find_element(by=By.XPATH,
                                                          value='/html/body/div/div/div/div/div/div[4]/div[1]/div/div/div/div/div[3]/div[3]/div/div/div[2]/div/div/div/div/div[1]/div/div/div[2]/div/div/div[5]/div/div/div[2]/details/summary').text
                    Confidentiality = microsoft_driver.find_element(by=By.XPATH,
                                                                    value='/html/body/div/div/div/div/div/div[4]/div[1]/div/div/div/div/div[3]/div[3]/div/div/div[2]/div/div/div/div/div[1]/div/div/div[2]/div/div/div[6]/div/div/div[2]/details/summary').text
                    Integrity = microsoft_driver.find_element(by=By.XPATH,
                                                              value='/html/body/div/div/div/div/div/div[4]/div[1]/div/div/div/div/div[3]/div[3]/div/div/div[2]/div/div/div/div/div[1]/div/div/div[2]/div/div/div[7]/div/div/div[2]/details/summary').text
                    Availability = microsoft_driver.find_element(by=By.XPATH,
                                                                 value='/html/body/div/div/div/div/div/div[4]/div[1]/div/div/div/div/div[3]/div[3]/div/div/div[2]/div/div/div/div/div[1]/div/div/div[2]/div/div/div[7]/div/div/div[2]/details/summary').text
                    Vector = cvss[0:8] + '/AV:' + AttackVector[0] + '/AC:' + AttackComplexity[0] + '/PR:' + \
                             PrivilegesRequired[0] + '/UI:' + \
                             UserInteraction[0] + '/S:' + Scope[0] + '/C:' + Confidentiality[0] + '/I:' + Integrity[
                                 0] + '/A:' + Availability[0]
                except:
                    pass
                if discriptons != None:
                    microsoft_cves[cve_id] = [discriptons, published_date, product_id.lower(), version, score, Vector]
            except:
                print('Error in MicrosoftCrawler :', cve_id)

        if (len(microsoft_cves.keys())) >= 1:

            for cve_id in (microsoft_cves.keys()):
                cveinfo = microsoft_cves[cve_id]
                try:
                    self.nvdcheck.update_one(cve_id)
                except:
                    pass
                cve_sh = self.Docs_Content.find_one({'cve_id': cve_id})
                if cve_sh != None:
                    # Update Doct
                    url = 'https://msrc.microsoft.com/update-guide/vulnerability/' + cve_id
                    cve_url = cve_sh['cve_url']
                    if cve_url == None:
                        cve_url = {'microsoft': url}
                    else:
                        cve_url = cve_url | {'microsoft': url}
                    # Update Docs_Content
                    # product_id
                    product_id_list = []
                    try:
                        product_id_list = [i for i in cve_sh['product_id']]
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
                        product_objs = self.Product.insert_one(
                            {'brand_id': brandid, 'product_id': cveinfo[2]}).inserted_id
                        if product_objs not in product_id_list:
                            product_id_list.append(product_objs)

                    if len(product_id_list) <= 0:
                        product_id_list = None

                    Docs_Content_Update = {
                        'product_id': product_id_list,
                        'modified_date': datetime.now(),
                        'cve_url': cve_url,
                    }
                    self.Docs_Content.update_one({'cve_id': cve_id}, {"$set": Docs_Content_Update})

                    # Update score

                    if self.Score.find_one({'cve_id': cve_id, 'source': 'microsoft'}) == None:
                        Insertdata = {
                            'cve_id': cve_id,
                            'titel': None,
                            'source': 'microsoft',
                            'score': float(cveinfo[4]),
                            # 'score_desc': self.score_desc(float(cveinfo[4])),
                            'vector': cveinfo[5],
                            'version': cveinfo[3],
                            'accessvector': None
                        }
                        self.Score.insert_one(Insertdata)
                else:
                    url = 'https://msrc.microsoft.com/update-guide/vulnerability/' + cve_id
                    cve_urls = {'microsoft': url}
                    # Insert to Docs_Content
                    # hyperlinks
                    product_id_list = []

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
                        product_objs = self.Product.insert_one(
                            {'brand_id': brandid, 'product_id': cveinfo[2]}).inserted_id
                        if product_objs not in product_id_list:
                            product_id_list.append(product_objs)

                    if len(product_id_list) <= 0:
                        product_id_list = None
                    published_date = cveinfo[1]

                    Insertdata = {
                        'cve_id': cve_id,
                        'year': published_date.year,
                        'month': published_date.month,
                        'cve_url': cve_urls,
                        'published_date': published_date,
                        'modified_date': datetime.now(),
                        'source': 'microsoft',
                        'discriptons': cveinfo[0],
                        'hyperlinks': None,
                        'cwe_id': None,
                        'product_id': product_id_list,
                    }
                    self.Docs_Content.insert_one(Insertdata)
                    # Insert to Score
                    x = float(cveinfo[4])
                    Insertdata = {
                        'cve_id': cve_id,
                        'titel': None,
                        'source': 'microsoft',
                        'score': float(cveinfo[4]),
                        # 'score_desc': self.score_desc(float(cveinfo[4])),
                        'vector': cveinfo[5],
                        'version': cveinfo[3],
                        'accessvector': None
                    }
                    self.Score.insert_one(Insertdata)
        try:
            microsoft_driver.close()
        except:
            pass

    def update_one(self, cve_id):
        microsoft_driver = webdriver.Chrome(service=self.chromedriver)
        microsoft_driver.minimize_window()
        cveurl = 'https://msrc.microsoft.com/update-guide/vulnerability/' + cve_id
        microsoft_driver.get(cveurl)
        time.sleep(10)
        discriptons = None
        try:
            discriptons = microsoft_driver.find_element(by=By.XPATH,
                                                        value='//*[@id="title"]/div/div/div/div[1]/div/div[1]/h1')
            discriptons = discriptons.text
        except:
            pass
        brand_id = 'microsoft'
        product_id = 'other'
        try:
            product_id = (microsoft_driver.find_element(by=By.XPATH,
                                                        value='/html/body/div/div/div/div/div/div[4]/div[5]/div/div/div/div/div/div/div[3]/div[2]/div/div[2]/div/div/div/div[2]/div/div/div/div/div/div/div/div/div[2]')).text
        except:
            pass
        version = None
        score = None
        try:
            cvss = (microsoft_driver.find_element(by=By.XPATH,
                                                  value='//*[@id="title"]/div/div/div/div[3]/div[1]/div/label')).text
            version = "V" + cvss[5:6]
            score = cvss[9:cvss.index('/') - 1]
        except:
            pass
        published_date = None
        try:
            published_date = (
                microsoft_driver.find_element(by=By.XPATH, value='//*[@id="title"]/div/div/div/p[1]')).text
            published_date = (published_date[published_date.index(':') + 2:]).replace(',', '')
            published_date = datetime.strptime(published_date, '%b %d %Y')
            published_date = datetime.strptime(published_date, '%Y-%m-%dT%H:%MZ')
        except:
            pass
        Vector = None
        try:
            AttackVector = microsoft_driver.find_element(by=By.XPATH,
                                                         value='/html/body/div/div/div/div/div/div[4]/div[1]/div/div/div/div/div[3]/div[3]/div/div/div[2]/div/div/div/div/div[1]/div/div/div[2]/div/div/div[1]/div/div/div[2]/details/summary').text
            AttackComplexity = microsoft_driver.find_element(by=By.XPATH,
                                                             value='/html/body/div/div/div/div/div/div[4]/div[1]/div/div/div/div/div[3]/div[3]/div/div/div[2]/div/div/div/div/div[1]/div/div/div[2]/div/div/div[2]/div/div/div[2]/details/summary').text
            PrivilegesRequired = microsoft_driver.find_element(by=By.XPATH,
                                                               value='/html/body/div/div/div/div/div/div[4]/div[1]/div/div/div/div/div[3]/div[3]/div/div/div[2]/div/div/div/div/div[1]/div/div/div[2]/div/div/div[3]/div/div/div[2]/details/summary').text
            UserInteraction = microsoft_driver.find_element(by=By.XPATH,
                                                            value='/html/body/div/div/div/div/div/div[4]/div[1]/div/div/div/div/div[3]/div[3]/div/div/div[2]/div/div/div/div/div[1]/div/div/div[2]/div/div/div[4]/div/div/div[2]/details/summary').text
            Scope = microsoft_driver.find_element(by=By.XPATH,
                                                  value='/html/body/div/div/div/div/div/div[4]/div[1]/div/div/div/div/div[3]/div[3]/div/div/div[2]/div/div/div/div/div[1]/div/div/div[2]/div/div/div[5]/div/div/div[2]/details/summary').text
            Confidentiality = microsoft_driver.find_element(by=By.XPATH,
                                                            value='/html/body/div/div/div/div/div/div[4]/div[1]/div/div/div/div/div[3]/div[3]/div/div/div[2]/div/div/div/div/div[1]/div/div/div[2]/div/div/div[6]/div/div/div[2]/details/summary').text
            Integrity = microsoft_driver.find_element(by=By.XPATH,
                                                      value='/html/body/div/div/div/div/div/div[4]/div[1]/div/div/div/div/div[3]/div[3]/div/div/div[2]/div/div/div/div/div[1]/div/div/div[2]/div/div/div[7]/div/div/div[2]/details/summary').text
            Availability = microsoft_driver.find_element(by=By.XPATH,
                                                         value='/html/body/div/div/div/div/div/div[4]/div[1]/div/div/div/div/div[3]/div[3]/div/div/div[2]/div/div/div/div/div[1]/div/div/div[2]/div/div/div[7]/div/div/div[2]/details/summary').text
            Vector = cvss[0:8] + '/AV:' + AttackVector[0] + '/AC:' + AttackComplexity[0] + '/PR:' + PrivilegesRequired[
                0] + '/UI:' + \
                     UserInteraction[0] + '/S:' + Scope[0] + '/C:' + Confidentiality[0] + '/I:' + Integrity[0] + '/A:' + \
                     Availability[0]
        except:
            pass
        if discriptons != None:
            cveinfo = [discriptons, published_date, product_id.lower(), version, score, Vector]

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
            product_id_list = [i for i in cve_sh['product_id']]
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
            'cve_url': cve_url,
        }
        self.Docs_Content.update_one({'cve_id': cve_id}, {"$set": Docs_Content_Update})

        # Update score

        if self.Score.find_one({'cve_id': cve_id, 'source': 'microsoft'}) == None:
            Insertdata = {
                'cve_id': cve_id,
                'titel': None,
                'source': 'microsoft',
                'score': float(cveinfo[4]),
                # 'score_desc': self.score_desc(float(cveinfo[4])),
                'vector': cveinfo[5],
                'version': cveinfo[3],
                'accessvector': None
            }
        self.Score.insert_one(Insertdata)
