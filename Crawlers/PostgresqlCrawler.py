import requests
from bs4 import BeautifulSoup
from . import Nvdapi, Viradb
import re
import dateutil.parser
from . import NvdCrawler


class PostgresqlCrawler():
    db = Viradb.Viradb()
    #
    Score = db.Score
    Docs_Content = db.Docs_Content
    CWE = db.CWE
    Brand = db.Brand
    Product = db.Product

    def getcve(self):
        url = 'https://www.postgresql.org/support/security/'
        headers = {
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.102 Safari/537.36'}
        page = requests.get(url, headers=headers, stream=True)
        soup = BeautifulSoup(page.content)
        cve_table = soup.find('table', attrs={'class': 'table table-striped'})
        cve_link = cve_table.find_all('span', attrs={'class': 'nobr'})

        brandid = (self.Brand.find_one({'brand_id': 'postgresql'}))['_id']
        poductid = (self.Product.find_one({'brand_id': brandid, 'product_id': 'postgresql'}))['_id']

        for item in cve_link:
            cve_id = item.text
            print('Start PostgresqlCrawler :', cve_id)
            # Doct
            cve_sh = self.Docs_Content.find_one({'cve_id': cve_id})
            if cve_sh == None:
                try:
                    obj = Nvdapi.getCVE(cve_id)
                except:
                    continue
                published_date = obj.publishedDate
                modified_date = obj.lastModifiedDate
                description_data = obj.cve.description.description_data[0]
                discriptons = description_data.value
                hyperlinks = [i.url for i in obj.cve.references.reference_data]
                cwe_id = [i.value for i in (obj.cwe[0]).description]
                Crawler = NvdCrawler.NVDCrawler(cve_id)
                source = Crawler.getSource()
                Scores = Crawler.getScore()

                # get vendors
                nodes = obj.configurations.nodes
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
                                if Product in Vendors_Products.keys():
                                    if Vendor not in Vendors_Products[Product]:
                                        Vendors_Products[Product].append(Vendor)
                                else:
                                    Vendors_Products[Product] = []
                                    if Vendor not in ['_', '-', '.']:
                                        Vendors_Products[Product].append(Vendor)
                    else:
                        for childs in nodes.children:
                            childs = childs.cpe_match
                            for cpe in childs:
                                item = cpe.cpe23Uri
                                itemIndex = [m.start() for m in re.finditer(':', item)]
                                Vendor = item[itemIndex[2] + 1:itemIndex[3]]
                                Product = item[itemIndex[3] + 1:itemIndex[4]]
                                if Product not in ['_', '-', '.']:
                                    if Product in Vendors_Products.keys():
                                        if Vendor not in Vendors_Products[Product]:
                                            Vendors_Products[Product].append(Vendor)
                                    else:
                                        Vendors_Products[Product] = ['noProduct']
                                        if Vendor not in ['_', '-', '.']:
                                            Vendors_Products[Product].append(Vendor)

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
                    else:
                        cveproductlist = None
                else:
                    cveproductlist = None

                if cveproductlist == None:
                    cveproductlist = poductid
                else:
                    cveproductlist.append(poductid)

                cveproductlist = list(set(cveproductlist))

                # Insert  to  CWE
                cwe_id_list = []
                if len(cwe_id) > 0:
                    for cwid in cwe_id:
                        searchitem = self.CWE.find_one({'cwe_id': cwid})
                        if searchitem == None:
                            postid = self.CWE.insert_one({'cwe_id': cwid}).inserted_id
                            cwe_id_list.append(postid)
                        else:
                            cwe_id_list.append(searchitem['_id'])
                # Insert  to  Docs
                Insertdata = {
                    'cve_id': cve_id,
                    'year': dateutil.parser.parse(published_date).strftime('%Y'),
                    'month': dateutil.parser.parse(published_date).strftime('%m'),
                    'cve_urls': {'nvd': 'https://nvd.nist.gov/vuln/detail/' + cve_id
                        , 'postgresql': 'https://www.postgresql.org/support/security/'
                                 }
                }

                # Insert to Docs_Content
                Insertdata = {
                    'cve_id': cve_id,
                    'year': dateutil.parser.parse(published_date).strftime('%Y'),
                    'month': dateutil.parser.parse(published_date).strftime('%m'),
                    'cve_urls': {'nvd': 'https://nvd.nist.gov/vuln/detail/' + cve_id,
                                 'postgresql': 'https://www.postgresql.org/support/security/',
                                 },
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
            else:
                products = (self.Docs_Content.find_one({'cve_id':cve_id}))['product_id']
                if products != None:
                    products.append(poductid)
                else:
                    products = [poductid]
                products = list(set(products))
                self.Docs_Content.update_one({'cve_id': cve_id}, {"$set": {'product_id': products}})
