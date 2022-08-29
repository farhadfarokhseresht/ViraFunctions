import datetime

from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from webdriver_manager.chrome import ChromeDriverManager
import time
from . import Viradb


class QualcommCrawler():
    db = Viradb.Viradb()
    #
    Score = db.Score
    Docs_Content = db.Docs_Content
    CWE = db.CWE
    Brand = db.Brand
    Product = db.Product
    chromedriver = Service(ChromeDriverManager().install())  # TODO get ChromeDriver in hostserver
    mainurl = 'https://docs.qualcomm.com/product/publicresources/securitybulletin/'

    def __init__(self):
        self.cveDate = None

    def getcve(self):
        print('QualcommCrawler Start')
        CVE_list = {}
        qualcomm_driver = webdriver.Chrome(service=self.chromedriver)
        qualcomm_driver.minimize_window()
        # qualcomm_driver = webdriver.Chrome(executable_path='chromedriver.exe')
        try:
            qualcomm_driver.get('https://docs.qualcomm.com/product/publicresources/securitybulletin')
        except:
            print('can not get QualcommCrawler url')
        time.sleep(15)
        qualcomm_driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
        try:
            allh3 = qualcomm_driver.find_elements(by=By.TAG_NAME, value='h3')
            h1 = qualcomm_driver.find_elements(by=By.TAG_NAME, value='h1')[0]
            if h1.get_attribute('class') == 'title inlineStyle topictitle1':
                self.cveDate = list(h1.text.split())
                self.cveDate = self.cveDate[0] + '-' + self.cveDate[1] + '-bulletin.html'
                qualcomm_url = {'qualcomm': self.mainurl + self.cveDate}
            for h3 in allh3:
                if h3.get_attribute('class') == 'sectiontitle':
                    cveid = h3.get_attribute('id').replace('_', '').upper()
                    cve_table = h3.find_element(by=By.XPATH, value="//h3[@id='" + h3.get_attribute('id') + "']/following-sibling::table")
                    cve_table_content = cve_table.find_elements(by=By.TAG_NAME, value='tr')
                    Description = ((cve_table_content[2]).find_elements(by=By.TAG_NAME, value='td'))[1]
                    Description = Description.text
                    Cwe = ((cve_table_content[4]).find_elements(by=By.TAG_NAME, value='td'))[1]
                    Cwe = Cwe.text
                    Cwe = (Cwe[0:Cwe.index(' ')]).lower()
                    accessvector = ((cve_table_content[5]).find_elements(by=By.TAG_NAME, value='td'))[1]
                    accessvector = accessvector.text
                    CVSSRating = ((cve_table_content[7]).find_elements(by=By.TAG_NAME, value='td'))[1]
                    CVSSRating = CVSSRating.text
                    CVSSScore = ((cve_table_content[8]).find_elements(by=By.TAG_NAME, value='td'))[1]
                    CVSSScore = CVSSScore.text
                    CVSSString = ((cve_table_content[9]).find_elements(by=By.TAG_NAME, value='td'))[1]
                    CVSSString = CVSSString.text
                    e = CVSSString.index('/')
                    s = CVSSString.index(':') + 1
                    CVSSSVesion = float(CVSSString[s:e])
                    DateReported = ((cve_table_content[11]).find_elements(by=By.TAG_NAME, value='td'))[1]
                    DateReported = DateReported.text
                    AffectedChipsets = ((cve_table_content[12]).find_elements(by=By.TAG_NAME, value='td'))[1]
                    AffectedChipsets = (AffectedChipsets.text).split(', ')
                    CVE_list[cveid] = [Description, accessvector, CVSSRating, CVSSScore, CVSSString, DateReported, AffectedChipsets, CVSSSVesion, Cwe]
        except:
            CVE_list = []
        # start
        qualcomm_driver.close()
        if len(CVE_list.keys()) > 0:
            for cve_id in CVE_list.keys():
                print('QualcommCrawler : ', cve_id)
                cve_info = CVE_list[cve_id]
                cve_sh = self.Docs_Content.find_one({'cve_id': cve_id})
                if cve_sh != None:
                    cve_id = cve_sh['_id']
                    # update Doct
                    cve_url = cve_sh['cve_url']
                    if cve_url == None:
                        cve_url = qualcomm_url
                    else:
                        cve_url = cve_url | qualcomm_url
                    # Update Docs_Content
                    ## cwe_id
                    cwe_id = cve_info[8].upper()
                    cwesh = self.CWE.find_one({'cwe_id': cwe_id})
                    if (cwesh != None):
                        cwe_id_id = cwesh['_id']
                    else:
                        cwe_id_id = self.CWE.insert_one({'cwe_id': cwe_id}).inserted_id

                    try:
                        if cve_sh['cwe_id'] == None:
                            cwe_update = [cwe_id_id]
                        else:
                            cwe_update = list(set(cve_sh['cwe_id'] + [cwe_id_id]))
                    except:
                        cwe_update = None

                    ## product_id
                    qualcomm_product_id_list = []
                    brandid = self.Brand.find_one({'brand_id': 'qualcomm'})
                    if brandid != None:
                        brandid = brandid['_id']
                    else:
                        brandid = self.Brand.insert_one({'brand_id': 'qualcomm'}).inserted_id
                    for prod in cve_info[6]:
                        prod = prod.lower()
                        product_objs = self.Product.find_one({'brand_id': brandid, 'product_id': prod})
                        if product_objs != None:
                            qualcomm_product_id_list.append(product_objs['_id'])
                        else:
                            product_objs = self.Product.insert_one({'brand_id': brandid, 'product_id': prod}).inserted_id
                            qualcomm_product_id_list.append(product_objs)

                    if len(qualcomm_product_id_list) <= 0:
                        product_update = None
                    else:
                        qualcomm_product_id_list = list(set(qualcomm_product_id_list))
                        if cve_sh['product_id'] == None:
                            product_update = qualcomm_product_id_list
                        else:
                            product_update = list(set(cve_sh['product_id'] + qualcomm_product_id_list))

                    Docs_Content_Update = {
                        'cve_url': cve_url,
                        'cwe_id': cwe_update,
                        'product_id': product_update,
                    }
                    self.Docs_Content.update_one({'cve_id': cve_id}, {"$set": Docs_Content_Update})
                    # Update score
                    if self.Score.find_one({'cve_id': cve_id, 'source': 'qualcomm'}) == None:
                        Insertdata = {
                            'cve_id': cve_id,
                            'titel': None,
                            'source': 'qualcomm',
                            'score': float(cve_info[3]),
                            'score_desc': cve_info[2],
                            'vector': cve_info[4],
                            'version': cve_info[8],
                            'accessvector': cve_info[1]
                        }
                        self.Score.insert_one(Insertdata)

                else:
                    # if not in db
                    # check for brand and product
                    qualcomm_product_id_list = []
                    brandid = self.Brand.find_one({'brand_id': 'qualcomm'})
                    if brandid != None:
                        brandid = brandid['_id']
                    else:
                        brandid = self.Brand.insert_one({'brand_id': 'qualcomm'}).inserted_id

                    for prod in cve_info[6]:
                        prod = prod.lower()
                        product_objs = self.Product.find_one({'brand_id': brandid, 'product_id': prod})
                        if product_objs != None:
                            qualcomm_product_id_list.append(product_objs['_id'])
                        else:
                            product_objs = self.Product.insert_one({'brand_id': brandid, 'product_id': prod}).inserted_id
                            qualcomm_product_id_list.append(product_objs)

                    if len(qualcomm_product_id_list) <= 0:
                        qualcomm_product_id_list = None
                    else:
                        qualcomm_product_id_list = list(set(qualcomm_product_id_list))

                    cwe_id = cve_info[8].upper()
                    cwesh = self.CWE.find_one({'cwe_id': cwe_id})
                    if (cwesh != None):
                        cwe_id_id = cwesh['_id']
                    else:
                        cwe_id_id = self.CWE.insert_one({'cwe_id': cwe_id}).inserted_id

                    # Insert  to  Docs_Content
                    Insertdata = {
                        'cve_id': cve_id,
                        'year': int(cve_info[5][:4]),
                        'month': int(cve_info[5][5:7]),
                        'cve_url': qualcomm_url,
                        'published_date': cve_info[5],
                        'modified_date': datetime.datetime.now(),
                        'source': 'qualcomm',
                        'discriptons': cve_info[0],
                        'hyperlinks': None,
                        'cwe_id': [cwe_id_id],
                        'product_id': qualcomm_product_id_list,
                    }

                    self.Docs_Content.insert_one(Insertdata)
                    # Insert to Score
                    Insertdata = {
                        'cve_id': cve_id,
                        'titel': None,
                        'source': 'qualcomm',
                        'score': float(cve_info[3]),
                        'score_desc': cve_info[2],
                        'vector': cve_info[4],
                        'version': cve_info[8],
                        'accessvector': cve_info[1]
                    }
                    self.Score.insert_one(Insertdata)
        print('QualcommCrawler End successfuly')

    def get_one_cve(self, cve_id, url):
        CVE_list = []
        qualcomm_driver = webdriver.Chrome(service=self.chromedriver)
        qualcomm_driver.minimize_window()
        # qualcomm_driver = webdriver.Chrome(executable_path='chromedriver.exe')
        try:
            qualcomm_driver.get(url)
        except:
            print('can not get QualcommCrawler url')
        time.sleep(15)
        qualcomm_driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
        try:
            allh3 = qualcomm_driver.find_elements(by=By.TAG_NAME, value='h3')
            for h3 in allh3:
                if h3.get_attribute('class') == 'sectiontitle':
                    cveid = h3.get_attribute('id').replace('_', '').upper()
                    if cveid == cve_id:
                        cve_table = h3.find_element(by=By.XPATH, value="//h3[@id='" + h3.get_attribute('id') + "']/following-sibling::table")
                        cve_table_content = cve_table.find_elements(by=By.TAG_NAME, value='tr')
                        Description = ((cve_table_content[2]).find_elements(by=By.TAG_NAME, value='td'))[1]
                        Description = Description.text
                        Cwe = ((cve_table_content[4]).find_elements(by=By.TAG_NAME, value='td'))[1]
                        Cwe = Cwe.text
                        Cwe = (Cwe[0:Cwe.index(' ')]).lower()  # todo
                        accessvector = ((cve_table_content[5]).find_elements(by=By.TAG_NAME, value='td'))[1]
                        accessvector = accessvector.text
                        CVSSRating = ((cve_table_content[7]).find_elements(by=By.TAG_NAME, value='td'))[1]
                        CVSSRating = CVSSRating.text
                        CVSSScore = ((cve_table_content[8]).find_elements(by=By.TAG_NAME, value='td'))[1]
                        CVSSScore = CVSSScore.text
                        CVSSString = ((cve_table_content[9]).find_elements(by=By.TAG_NAME, value='td'))[1]
                        CVSSString = CVSSString.text
                        e = CVSSString.index('/')
                        s = CVSSString.index(':') + 1
                        CVSSSVesion = float(CVSSString[s:e])
                        DateReported = ((cve_table_content[11]).find_elements(by=By.TAG_NAME, value='td'))[1]
                        DateReported = DateReported.text
                        AffectedChipsets = ((cve_table_content[12]).find_elements(by=By.TAG_NAME, value='td'))[1]
                        AffectedChipsets = (AffectedChipsets.text).split(', ')
                        CVE_list[cveid] = [Description, accessvector, CVSSRating, CVSSScore, CVSSString, DateReported, AffectedChipsets, CVSSSVesion,
                                           Cwe]
                    else:
                        pass
        except:
            CVE_list = []
        # start
        qualcomm_driver.close()
        if len(CVE_list) > 0:
            for cve_id in CVE_list.keys():
                print('QualcommCrawler : ', cve_id)
                cve_info = CVE_list[cve_id]
                cve_sh = self.Docs_Content.find_one({'cve_id': cve_id})
                if cve_sh != None:
                    print('cve is not in db !')
                else:
                    # if not in db
                    # Insert  to  Docs

                    # check for brand and product
                    qualcomm_product_id_list = []
                    brandid = self.Brand.find_one({'brand_id': 'qualcomm'})
                    if brandid != None:
                        brandid = brandid['_id']
                    else:
                        brandid = self.Brand.insert_one({'brand_id': 'qualcomm'}).inserted_id

                    for prod in cve_info[6]:
                        prod = prod.lower()
                        product_objs = self.Product.find_one({'brand_id': brandid, 'product_id': prod})
                        if product_objs != None:
                            qualcomm_product_id_list.append(product_objs['_id'])
                        else:
                            product_objs = self.Product.insert_one({'brand_id': brandid, 'product_id': prod}).inserted_id
                            qualcomm_product_id_list.append(product_objs)

                    if len(qualcomm_product_id_list) <= 0:
                        qualcomm_product_id_list = None
                    else:
                        qualcomm_product_id_list = list(set(qualcomm_product_id_list))

                    cwe_id = cve_info[8].upper()
                    cwesh = self.CWE.find_one({'cwe_id': cwe_id})
                    if (cwesh != None):
                        cwe_id_id = cwesh['_id']
                    else:
                        cwe_id_id = self.CWE.insert_one({'cwe_id': cwe_id}).inserted_id

                    # Insert  to  Docs_Content
                    Insertdata = {
                        'cve_id': cve_id,
                        'year': int(cve_info[5][:4]),
                        'month': int(cve_info[5][5:7]),
                        'published_date': cve_info[5],
                        'modified_date': datetime.datetime.now(),
                        'source': 'qualcomm',
                        'discriptons': cve_info[0],
                        'hyperlinks': None,
                        'cwe_id': [cwe_id_id],
                        'product_id': qualcomm_product_id_list,
                    }

                    self.Docs_Content.insert_one(Insertdata)
                    # Insert to Score
                    Insertdata = {
                        'cve_id': cve_id,
                        'titel': None,
                        'source': 'qualcomm',
                        'score': float(cve_info[3]),
                        'score_desc': cve_info[2],
                        'vector': cve_info[4],
                        'version': cve_info[8],
                        'accessvector': cve_info[1]
                    }
                    self.Score.insert_one(Insertdata)
        print('QualcommCrawler End successfuly')
