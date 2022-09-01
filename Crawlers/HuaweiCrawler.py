import requests
from bs4 import BeautifulSoup
import NvdCrawler, Viradb
from datetime import datetime


class HuaweiCrawler():
    db = Viradb.Viradb()
    #
    Score = db.Score
    Docs_Content = db.Docs_Content
    CWE = db.CWE
    Brand = db.Brand
    Product = db.Product
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
        now = datetime.now()
        # url = 'https://consumer.huawei.com/en/support/bulletin/{}/{}/'.format(now.year,now.month)
        url = 'https://consumer.huawei.com/en/support/bulletin/2022/8/'#.format(now.year,now.month)
        headers = {
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.102 Safari/537.36'}
        page = requests.get(url, headers=headers, stream=True)
        soup = BeautifulSoup(page.content)
        cve_list = {}
        all_p_tag = soup.find_all('p', attrs={'class': 'titile-size'})
        for ptag in all_p_tag:
            if (ptag.text).find('CVE-') >= 0:
                ptag_txt = ptag.text
                cve_id = ptag_txt[:ptag_txt.index(':')]
                # cwe_txt = ptag_txt[ptag_txt.index(':'):]
                Severity = ptag.next.next.next.text
                Severity = Severity[Severity.index(':') + 1:].replace(' ', '')
                Affectedversions = ptag.next.next.next.next.next.next.text
                Affectedversions = Affectedversions[Affectedversions.index(':') + 2:].split(',')
                Affectedversions = [i[1:] for i in Affectedversions]
                cve_list[cve_id] = [url, Severity, Affectedversions]

        if len(cve_list.keys()) > 0 :
            for cve_id in cve_list.keys() :
                try:
                    self.nvdcheck.update_one(cve_id)
                except:
                    break
                cve_info = cve_list[cve_id]
                cve_sh = self.Docs_Content.find_one({'cve_id': cve_id})
                if cve_sh != None:
                    # update Doct
                    cve_url = cve_sh['cve_url']
                    if cve_url == None:
                        cve_url = {'huawei': cve_info[0]}
                    else:
                        cve_url = cve_url | {'huawei': cve_info[0]}
                    # product_id
                    product_id_list = []
                    brandid = self.Brand.find_one({'brand_id': 'huawei'})
                    if brandid != None:
                        brandid = brandid['_id']
                    else:
                        brandid = self.Brand.insert_one({'brand_id': 'huawei'}).inserted_id

                    try:
                        for prod in cve_info[2]:
                            prod = prod.lower().replace(' ','_')
                            product_objs = self.Product.find_one({'brand_id': brandid, 'product_id': prod})
                            if product_objs != None:
                                product_id_list.append(product_objs['_id'])
                            else:
                                product_objs = self.Product.insert_one({'brand_id': brandid, 'product_id': prod}).inserted_id
                                product_id_list.append(product_objs)
                    except:
                        product_objs = self.Product.insert_one({'brand_id': brandid, 'product_id': 'huawei_other'}).inserted_id
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
                        'cve_url': cve_url,
                        'product_id': product_update,
                    }
                    self.Docs_Content.update_one({'cve_id': cve_id}, {"$set": Docs_Content_Update})
                    # Update score

                    list_score_desc = {'High': 7.8, 'Low': 3.3, 'Medium': 6, 'Critical': 9.8, 'Negligible': None}
                    score = list_score_desc[cve_info[1]]
                    if self.Score.find_one({'cve_id': cve_id, 'source': 'huawei'}) == None:
                        Insertdata = {
                            'cve_id': cve_id,
                            'titel': None,
                            'source': 'huawei',
                            'score': score,
                            'score_desc': cve_info[1],
                            'vector': None,
                            'version': 'V3',
                            'accessvector': None
                        }
                        self.Score.insert_one(Insertdata)
                else:
                    pass
                    # if not in db
                    # NO INFORMATION
        else:
            print('HuaweiCrawler cant find any cve')