import datetime
import Nvdapi, Viradb
import re
import requests
from bs4 import BeautifulSoup


class NVDCrawler():
    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.102 Safari/537.36'}
    page = None
    soup = None

    def __init__(self, cve_id):
        self.cve_id = cve_id
        self.url = 'https://nvd.nist.gov/vuln/detail/' + cve_id
        self.page = requests.get(self.url, headers=self.headers)
        if self.page.status_code == 200:
            self.soup = BeautifulSoup(self.page.content, features="html.parser")
        else:
            self.page = requests.get(self.url, headers=self.headers, timeout=10)
            self.soup = BeautifulSoup(self.page.content, features="html.parser")

    def getScore(self):
        Cvss = ['Vuln2CvssPanel', 'Vuln3CvssPanel']
        cve_id_Scorelist = []
        for pid in Cvss:
            try:
                CvssPanel = self.soup.find(id=pid)
            except:
                self.page = requests.get(self.url, headers=self.headers, timeout=10)
                self.soup = BeautifulSoup(self.page.content, features="html.parser")
                CvssPanel = self.soup.find(id=pid)

            try:
                rowgutters = CvssPanel.find_all('div', {'class': 'row no-gutters'})
            except:
                rowgutters = CvssPanel.find('div', {'class': 'row no-gutters'})

            for row in rowgutters:
                Score = {'version': None, 'titel': None, 'source': None, 'score': None,
                         'score_desc': None,
                         'vector': None, 'accessvector': None}
                if pid == 'Vuln2CvssPanel':
                    Score['version'] = 'V2'
                else:
                    Score['version'] = 'V3'
                div = row.find_all('div', attrs={'class': 'col-lg-3 col-sm-6'})
                Score_titel = str(div[0].find('strong').text).replace(':', "").replace(' ', '')
                Score_source = div[0].find('span').text
                Score['titel'] = Score_titel
                Score['source'] = Score_source
                BaseScore = row.find('span', attrs={'class': 'severityDetail'}).text
                if BaseScore.find('N/A') >= 0:
                    Score['score'] = None
                    Score['score_desc'] = None
                else:
                    BaseScore = BaseScore.split(" ")
                    Score['score'] = float(BaseScore[1])
                    Score['score_desc'] = str(BaseScore[2]).replace('\n', '')

                div = row.find('div', attrs={'class': 'col-lg-6 col-sm-12'})
                vector = div.find('span')
                if (vector.text).find('not yet') > 0:
                    Score['vector'] = None
                else:
                    Score['vector'] = vector.find('span').text
                cve_id_Scorelist.append(Score)

        return cve_id_Scorelist

    def getSource(self):
        source = None
        try:
            source = str(self.soup.find('span', attrs={'data-testid': 'vuln-current-description-source'}))
            source = source[source.find('">') + 2:source.find('</span>')]
        except:
            pass
        return source


class NvdCrawler():
    db = Viradb.Viradb()
    #
    Score = db.Score
    Docs_Content = db.Docs_Content
    CWE = db.CWE
    Brand = db.Brand
    Product = db.Product

    keys = '674532ec-c518-46ab-8896-f5be5fca1664'

    # to find and insert new data
    def getcve(self, chekdays=1):
        # max interval
        if chekdays > 120:
            chekdays = 120
        end = datetime.datetime.now()
        start = end - datetime.timedelta(days=chekdays)
        objects = Nvdapi.searchCVE(modStartDate=start, modEndDate=end, key=self.keys)
        for obj in objects:
            cve_id = obj.id
            cve_sh = self.Docs_Content.find_one({'cve_id': cve_id})
            if cve_sh == None:
                published_date = datetime.datetime.strptime(obj.publishedDate, '%Y-%m-%dT%H:%MZ')
                modified_date = datetime.datetime.now()
                description_data = obj.cve.description.description_data[0]
                discriptons = description_data.value
                hyperlinks = [i.url for i in obj.cve.references.reference_data]
                cwe_id = [i.value for i in (obj.cwe[0]).description]
                Crawler = NVDCrawler(cve_id)
                source = Crawler.getSource()
                Scores = Crawler.getScore()
                # get vendors
                nodes = obj.configurations.nodes
                cveproductlist = None
                if len(nodes) > 0:
                    nodes = nodes[0]
                    Vendors_Products = {}
                    cveproductlist = []
                    if len(nodes.cpe_match) > 0:
                        for cpe in nodes.cpe_match:
                            item = str(cpe.cpe23Uri)
                            itemIndex = [m.start() for m in re.finditer(':', item)]
                            Vendor = item[itemIndex[2] + 1:itemIndex[3]]
                            Product = item[itemIndex[3] + 1:itemIndex[4]]
                            if Product not in ['_', '-', '.']:
                                if Vendor in Vendors_Products.keys():
                                    if Product not in Vendors_Products[Vendor]:
                                        Vendors_Products[Vendor].append(Product)
                                else:
                                    Vendors_Products[Vendor] = []
                                    if Vendor not in ['_', '-', '.']:
                                        Vendors_Products[Vendor].append(Product)
                    else:
                        for childs in nodes.children:
                            childs = childs.cpe_match
                            for cpe in childs:
                                item = cpe.cpe23Uri
                                itemIndex = [m.start() for m in re.finditer(':', item)]
                                Vendor = item[itemIndex[2] + 1:itemIndex[3]]
                                Product = item[itemIndex[3] + 1:itemIndex[4]]
                                if Vendor not in ['_', '-', '.']:
                                    if Vendor in Vendors_Products.keys():
                                        if Product not in Vendors_Products[Vendor]:
                                            Vendors_Products[Vendor].append(Product)
                                    elif (Product not in ['_', '-', '.']):
                                        Vendors_Products[Vendor] = [Product]
                                    else:
                                        Vendors_Products[Vendor] = ['other']

                    # insert to Brand and Products
                    if len(Vendors_Products) > 0:
                        for brand_id in Vendors_Products.keys():
                            brandsh = self.Brand.find_one({'brand_id': brand_id})
                            if brandsh == None:
                                # brand_id_ObjectId = self.Brand.insert_one({'brand_id': brand_id}).inserted_id
                                # for productitem in Vendors_Products[brand_id]:
                                #     productsh = self.Product.find_one({'brand_id': brand_id_ObjectId, 'product_id': productitem})
                                #     if productsh == None:
                                #         product_ObjectId = self.Product.insert_one(
                                #             {'brand_id': brand_id_ObjectId, 'product_id': productitem}).inserted_id
                                #         cveproductlist.append(product_ObjectId)
                                #     else:
                                #         product_ObjectId = productsh['_id']
                                #         cveproductlist.append(product_ObjectId)
                                continue
                            else:
                                brand_id_ObjectId = brandsh['_id']
                                for productitem in Vendors_Products[brand_id]:
                                    productsh = self.Product.find_one(
                                        {'brand_id': brand_id_ObjectId, 'product_id': productitem})
                                    if productsh == None:
                                        product_ObjectId = self.Product.insert_one(
                                            {'brand_id': brand_id_ObjectId, 'product_id': productitem}).inserted_id
                                        cveproductlist.append(product_ObjectId)
                                    else:
                                        product_ObjectId = productsh['_id']
                                        cveproductlist.append(product_ObjectId)
                    # check Docs_Content for brands
                    cveproductid = self.Docs_Content.find_one({'cve_id': cve_id})
                    if cveproductid != None and cveproductlist != None:
                        cveproductid = cveproductid['product_id']
                        cveproductlist = list(set(cveproductlist + cveproductid))

                # Insert  to  CWE
                cwe_id_list = None
                if len(cwe_id) > 0:
                    cwe_id_list = []
                    for cwid in cwe_id:
                        searchitem = self.CWE.find_one({'cwe_id': cwid})
                        if searchitem == None:
                            postid = self.CWE.insert_one({'cwe_id': cwid}).inserted_id
                            cwe_id_list.append(postid)
                        else:
                            cwe_id_list.append(searchitem['_id'])
                if not cveproductlist:
                    cveproductlist=None
                print(cveproductlist)
                # Insert to Docs_Content
                Insertdata = {
                    'year': published_date.year,
                    'month': published_date.month,
                    'cve_url': {'nvd': 'https://nvd.nist.gov/vuln/detail/' + cve_id},
                    'cve_id': cve_id,
                    'published_date': published_date,
                    'modified_date': modified_date,
                    'source': source,
                    'discriptons': discriptons,
                    'hyperlinks': hyperlinks,
                    'cwe_id': cwe_id_list,
                    'product_id': cveproductlist,
                }
                self.Docs_Content.insert_one(Insertdata)
                # Insert to Score
                for item in Scores:
                    Insertdata = {
                        'cve_id': cve_id,
                        'titel': item['titel'],
                        'source': item['source'],
                        'score': item['score'],
                        'score_desc': item['score_desc'],
                        'vector': item['vector'],
                        'version': item['version'],
                        'accessvector': None
                    }
                    self.Score.insert_one(Insertdata)
                print('nvd get cve :', cve_id)
            else:
                self.update_one(cve_id)
                print('nvd get cve update :', cve_id)

    # to update al table lof one cve
    def update_one(self, cve_id, description_farsi=None):
        obj = Nvdapi.getCVE(cve_id, True, self.keys)
        cve_sh = self.Docs_Content.find_one({'cve_id': cve_id})
        if cve_sh != None:
            modified_date = datetime.datetime.now()
            published_date = datetime.datetime.strptime(obj.publishedDate, '%Y-%m-%dT%H:%MZ')
            description_data = obj.cve.description.description_data[0]
            discriptons = description_data.value
            hyperlinks = [i.url for i in obj.cve.references.reference_data]
            cwe_id = [i.value for i in (obj.cwe[0]).description]
            Crawler = NVDCrawler(cve_id)
            source = Crawler.getSource()
            Scores = Crawler.getScore()
            cve_url = cve_sh['cve_url']
            if cve_url == None:
                cve_url = {'nvd': 'https://nvd.nist.gov/vuln/detail/' + cve_id}
            else:
                cve_url = cve_url | {'nvd': 'https://nvd.nist.gov/vuln/detail/' + cve_id}
            # get vendors
            nodes = obj.configurations.nodes
            cveproductlist = None
            if len(nodes) > 0:
                nodes = nodes[0]
                Vendors_Products = {}
                cveproductlist = []
                if len(nodes.cpe_match) > 0:
                    for cpe in nodes.cpe_match:
                        item = str(cpe.cpe23Uri)
                        itemIndex = [m.start() for m in re.finditer(':', item)]
                        Vendor = item[itemIndex[2] + 1:itemIndex[3]]
                        Product = item[itemIndex[3] + 1:itemIndex[4]]
                        if Vendor not in ['_', '-', '.']:
                            if Vendor in Vendors_Products.keys():
                                if Product not in Vendors_Products[Vendor]:
                                    if Vendor not in ['_', '-', '.']:
                                        Vendors_Products[Vendor].append(Product)
                            else:
                                Vendors_Products[Vendor] = []
                                if Product not in ['_', '-', '.']:
                                    Vendors_Products[Vendor].append(Product)
                else:
                    for childs in nodes.children:
                        childs = childs.cpe_match
                        for cpe in childs:
                            item = cpe.cpe23Uri
                            itemIndex = [m.start() for m in re.finditer(':', item)]
                            Vendor = item[itemIndex[2] + 1:itemIndex[3]]
                            Product = item[itemIndex[3] + 1:itemIndex[4]]
                            if Vendor not in ['_', '-', '.']:
                                if Vendor in Vendors_Products.keys():
                                    if Product not in Vendors_Products[Vendor]:
                                        Vendors_Products[Vendor].append(Product)
                                elif (Product not in ['_', '-', '.']):
                                    Vendors_Products[Vendor] = [Product]
                                else:
                                    Vendors_Products[Vendor] = ['other']

                # insert to Brand and Products
                if len(Vendors_Products) > 0:
                    for brand_id in Vendors_Products.keys():
                        brandsh = self.Brand.find_one({'brand_id': brand_id})
                        if brandsh == None:
                            # brand_id_ObjectId = self.Brand.insert_one({'brand_id': brand_id}).inserted_id
                            # for productitem in Vendors_Products[brand_id]:
                            #     productsh = self.Product.find_one({'brand_id': brand_id_ObjectId, 'product_id': productitem})
                            #     if productsh == None:
                            #         product_ObjectId = self.Product.insert_one({'brand_id': brand_id_ObjectId, 'product_id': productitem}).inserted_id
                            #         cveproductlist.append(product_ObjectId)
                            #     else:
                            #         product_ObjectId = productsh['_id']
                            #         cveproductlist.append(product_ObjectId)
                            continue
                        else:
                            brand_id_ObjectId = brandsh['_id']
                            for productitem in Vendors_Products[brand_id]:
                                productsh = self.Product.find_one(
                                    {'brand_id': brand_id_ObjectId, 'product_id': productitem})
                                if productsh == None:
                                    product_ObjectId = self.Product.insert_one(
                                        {'brand_id': brand_id_ObjectId, 'product_id': productitem}).inserted_id
                                    cveproductlist.append(product_ObjectId)
                                else:
                                    product_ObjectId = productsh['_id']
                                    cveproductlist.append(product_ObjectId)
                # check Docs_Content for brands
                cveproductid = self.Docs_Content.find_one({'cve_id': cve_id})
                if cveproductid != None and cveproductlist != None:
                    cveproductid = cveproductid['product_id']
                    if cveproductid != None:
                        cveproductlist = list(set(cveproductlist + cveproductid))
                    else:
                        cveproductlist = list(set(cveproductlist))

            # Insert  to  CWE
            cwe_id_list = None
            cweobj = self.Docs_Content.find_one({'cve_id': cve_id})
            if len(cwe_id) > 0:
                cwe_id_list = []
                for cwid in cwe_id:
                    searchitem = self.CWE.find_one({'cwe_id': cwid})
                    if searchitem == None:
                        postid = self.CWE.insert_one({'cwe_id': cwid}).inserted_id
                        cwe_id_list.append(postid)
                    else:
                        cwe_id_list.append(searchitem['_id'])
                if (cweobj != None):
                    cweobj = cweobj['cwe_id']
                    if (cweobj != None):
                        cwe_id_list = list(set(cweobj + cwe_id_list))
                    else:
                        cwe_id_list = list(set(cwe_id_list))

            elif (cweobj != None):
                cwe_id_list = cweobj['cwe_id']

            # Update Docs_Content

            Updatedata = {
                'cve_url': cve_url,
                'modified_date': modified_date,
                'published_date': published_date,
                'source': source,
                'discriptons': discriptons,
                'description_farsi': description_farsi,
                'hyperlinks': hyperlinks,
                'cwe_id': cwe_id_list,
                'product_id': cveproductlist,
            }
            self.Docs_Content.update_one({'cve_id': cve_id}, {"$set": Updatedata})

            # Update to Score
            if len(Scores) > 0:
                for item in Scores:
                    # self.Score.delete_many(({'$and': [{'cve_id': cve_id}, {}]}))
                    Updatedata = dict(cve_id=cve_id, titel=item['titel'], source=item['source'], score=item['score'],
                                      score_desc=item['score_desc'], vector=item['vector'], version=item['version'])
                    # self.Score.insert_one(Updatedata)
                    self.Score.update_one({'cve_id': 'cve_id', 'source': item['source']}, {"$set": Updatedata})
            print(cve_id, "update down")
        else:
            cve_id = obj.id
            published_date = datetime.datetime.strptime(obj.publishedDate, '%Y-%m-%dT%H:%MZ')
            modified_date = datetime.datetime.now()
            description_data = obj.cve.description.description_data[0]
            discriptons = description_data.value
            hyperlinks = [i.url for i in obj.cve.references.reference_data]
            cwe_id = [i.value for i in (obj.cwe[0]).description]
            Crawler = NVDCrawler(cve_id)
            source = Crawler.getSource()
            Scores = Crawler.getScore()
            # get vendors
            nodes = obj.configurations.nodes
            cveproductlist = None
            if len(nodes) > 0:
                nodes = nodes[0]
                Vendors_Products = {}
                cveproductlist = []
                if len(nodes.cpe_match) > 0:
                    for cpe in nodes.cpe_match:
                        item = str(cpe.cpe23Uri)
                        itemIndex = [m.start() for m in re.finditer(':', item)]
                        Vendor = item[itemIndex[2] + 1:itemIndex[3]]
                        Product = item[itemIndex[3] + 1:itemIndex[4]]
                        if Product not in ['_', '-', '.']:
                            if Vendor in Vendors_Products.keys():
                                if Product not in Vendors_Products[Vendor]:
                                    Vendors_Products[Vendor].append(Product)
                            else:
                                Vendors_Products[Vendor] = []
                                if Vendor not in ['_', '-', '.']:
                                    Vendors_Products[Vendor].append(Product)
                else:
                    for childs in nodes.children:
                        childs = childs.cpe_match
                        for cpe in childs:
                            item = cpe.cpe23Uri
                            itemIndex = [m.start() for m in re.finditer(':', item)]
                            Vendor = item[itemIndex[2] + 1:itemIndex[3]]
                            Product = item[itemIndex[3] + 1:itemIndex[4]]
                            if Vendor not in ['_', '-', '.']:
                                if Vendor in Vendors_Products.keys():
                                    if Product not in Vendors_Products[Vendor]:
                                        Vendors_Products[Vendor].append(Product)
                                elif (Product not in ['_', '-', '.']):
                                    Vendors_Products[Vendor] = [Product]
                                else:
                                    Vendors_Products[Vendor] = ['other']

                # insert to Brand and Products
                if len(Vendors_Products) > 0:
                    for brand_id in Vendors_Products.keys():
                        brandsh = self.Brand.find_one({'brand_id': brand_id})
                        if brandsh == None:
                            brand_id_ObjectId = self.Brand.insert_one({'brand_id': brand_id}).inserted_id
                            for productitem in Vendors_Products[brand_id]:
                                productsh = self.Product.find_one(
                                    {'brand_id': brand_id_ObjectId, 'product_id': productitem})
                                if productsh == None:
                                    product_ObjectId = self.Product.insert_one(
                                        {'brand_id': brand_id_ObjectId, 'product_id': productitem}).inserted_id
                                    cveproductlist.append(product_ObjectId)
                                else:
                                    product_ObjectId = productsh['_id']
                                    cveproductlist.append(product_ObjectId)
                        else:
                            brand_id_ObjectId = brandsh['_id']
                            for productitem in Vendors_Products[brand_id]:
                                productsh = self.Product.find_one(
                                    {'brand_id': brand_id_ObjectId, 'product_id': productitem})
                                if productsh == None:
                                    product_ObjectId = self.Product.insert_one(
                                        {'brand_id': brand_id_ObjectId, 'product_id': productitem}).inserted_id
                                    cveproductlist.append(product_ObjectId)
                                else:
                                    product_ObjectId = productsh['_id']
                                    cveproductlist.append(product_ObjectId)
                # check Docs_Content for brands
                cveproductid = self.Docs_Content.find_one({'cve_id': cve_id})
                if cveproductid != None and cveproductlist != None:
                    cveproductid = cveproductid['product_id']
                    cveproductlist = list(set(cveproductlist + cveproductid))

            # Insert  to  CWE
            cwe_id_list = None
            if len(cwe_id) > 0:
                cwe_id_list = []
                for cwid in cwe_id:
                    searchitem = self.CWE.find_one({'cwe_id': cwid})
                    if searchitem == None:
                        postid = self.CWE.insert_one({'cwe_id': cwid}).inserted_id
                        cwe_id_list.append(postid)
                    else:
                        cwe_id_list.append(searchitem['_id'])

            # Insert to Docs_Content
            Insertdata = {
                'cve_id': cve_id,
                'year': published_date.year,
                'month': published_date.month,
                'cve_url': {'nvd': 'https://nvd.nist.gov/vuln/detail/' + cve_id},
                'published_date': published_date,
                'modified_date': modified_date,
                'source': source,
                'discriptons': discriptons,
                'description_farsi': description_farsi,
                'hyperlinks': hyperlinks,
                'cwe_id': cwe_id_list,
                'product_id': cveproductlist,
            }
            self.Docs_Content.insert_one(Insertdata)
            # Insert to Score
            for item in Scores:
                Insertdata = {
                    'cve_id': cve_id,
                    'titel': item['titel'],
                    'source': item['source'],
                    'score': float(item['score']),
                    'score_desc': item['score_desc'],
                    'vector': item['vector'],
                    'version': item['version'],
                    'accessvector': None
                }
                self.Score.insert_one(Insertdata)
            print('nvd get cve :', cve_id)
x= NvdCrawler()
x.getcve(1)