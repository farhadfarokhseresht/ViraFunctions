import nltk
import string
from nltk.tokenize import word_tokenize
from nltk.stem import PorterStemmer
from nltk.stem import WordNetLemmatizer
import pandas as pd
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.feature_extraction.text import TfidfTransformer
import pymongo
import datetime
import Viradb

nltk.download("punkt")
nltk.download('stopwords')


# TextPreprocessing

def TextPreprocessing(text, method=False, Notokenize=True):
    porter_stemmer = PorterStemmer()
    wordnet_lemmatizer = WordNetLemmatizer()
    # Punctuation Removal
    # preproces_txt = "".join([i for i in text if i not in string.punctuation + '0123456789' ])
    preproces_txt = text
    for i in string.punctuation + '0123456789':
        preproces_txt = preproces_txt.replace(i, ' ')
    # Lowering the text
    preproces_txt = preproces_txt.lower()
    # Tokenization
    preproces_txt = word_tokenize(preproces_txt)
    # Stop word removal
    stopwords = nltk.corpus.stopwords.words('english')
    preproces_txt = [i for i in preproces_txt if i not in stopwords]
    # remove words less than three letters
    preproces_txt = [word for word in preproces_txt if len(word) >= 4]

    if method == 's':
        # Stemming
        preproces_txt = [porter_stemmer.stem(word) for word in preproces_txt]
    elif method == 'l':
        # Lemmatization
        preproces_txt = [wordnet_lemmatizer.lemmatize(word) for word in preproces_txt]
    elif method == False:
        pass

    if Notokenize == True:
        preproces_txt = ' '.join(preproces_txt)
        preproces_txt = ' '.join(dict.fromkeys(preproces_txt.split()))

    return preproces_txt


def VendorPreprocessing(preproces_txt, Notokenize=False):
    preproces_txt = str(preproces_txt)
    # Punctuation Removal
    preproces_txt = "".join([i for i in preproces_txt if i not in string.punctuation + '0123456789'])
    # Lowering the text

    preproces_txt = preproces_txt.lower()
    if Notokenize == True:
        # Tokenization
        preproces_txt = word_tokenize(preproces_txt)

    return preproces_txt


def ProductPreprocessing(preproces_txt, Notokenize=False):
    # Punctuation Removal
    preproces_txt = "".join(
        [i for i in preproces_txt if
         i not in string.punctuation.replace('-', "").replace('.', "").replace('_', "")])  # + '0123456789'
    # Lowering the text
    preproces_txt = preproces_txt.lower()
    if Notokenize == True:
        # Tokenization
        preproces_txt = word_tokenize(preproces_txt)

    return preproces_txt


# keyword extractions
def get_all_keyword(data, vocab):
    language = "en"
    max_ngram_size = 2
    deduplication_thresold = 0.9
    deduplication_algo = 'seqm'
    windowSize = 1
    numOfKeywords = 20
    text = TextPreprocessing(" ".join(data))
    if len(vocab) > 0:
        cv = CountVectorizer(vocabulary=vocab, ngram_range=(1, 2), max_df=0.9, min_df=0.2, stop_words='english')
    else:
        cv = CountVectorizer(ngram_range=(1, 2), stop_words='english')
    word_count_vector = cv.fit_transform(data)
    tfidf_transformer = TfidfTransformer(smooth_idf=True, use_idf=True)
    tfidf_transformer.fit(word_count_vector)
    # get feature names
    feature_names = cv.get_feature_names_out()
    return set(feature_names)


# Predictions Function
class BrandPredictions():
    db = Viradb.Viradb()
    #
    Score = db.Score
    Docs_Content = db.Docs_Content
    CWE = db.CWE
    Brand = db.Brand
    Product = db.Product

    doc_objs = Docs_Content.find({'product_id': {'$ne': None}})
    df = []
    for obj in doc_objs:
        discriptons = obj['discriptons']
        brands = []
        try:
            if (len(obj['product_id']) > 0) and (isinstance(obj['product_id'], list)):
                for prods in obj['product_id']:
                    try:
                        brandid = (Product.find_one({'_id': prods}))['brand_id']
                        brand_name = (Brand.find_one({'_id': brandid}))['brand_id']
                        if brand_name not in brands:
                            brands.append(brand_name)
                    except:
                        pass
                for brand_name in brands:
                    df.append([discriptons, brand_name])
        except:
            pass
    #
    df = pd.DataFrame(df, columns=['text', 'vendor'])
    unic_vnd_list = set(df.vendor)

    vnd_keyword = {}
    for vend in unic_vnd_list:
        vocab = []
        kyex_data = df[df.vendor == vend].text
        kyex_data = kyex_data.map(lambda x: TextPreprocessing(x))
        vnd_keyword[vend] = get_all_keyword(kyex_data, vocab)

    brandobjs = Brand.find({})
    brand_product = {}
    for item in brandobjs:
        brandobjid = item['_id']
        vendor = VendorPreprocessing(item['brand_id'])
        product = []
        Productobjs = Product.find({'brand_id': brandobjid})
        for i in Productobjs:
            if i['product_id'] not in product:
                product.append(ProductPreprocessing(i['product_id']))
        brand_product[vendor] = product

    def predictVndors(self, discriptons):
        vnd_keyword = self.vnd_keyword
        brand_product = self.brand_product
        # Decision
        Decision = {}
        predict_brand = []
        # step 1 : check for brands
        discriptons_tokens = VendorPreprocessing(discriptons, True)
        discriptons_tokens = set(discriptons_tokens)
        for brand_name in list(brand_product.keys()):
            for token in discriptons_tokens:
                if token == brand_name:
                    predict_brand.append(brand_name)

        # step 2 : check for Product
        discriptons_tokens = ProductPreprocessing(discriptons, True)
        discriptons_tokens = set(discriptons_tokens)
        for x_brand, y_productlist in brand_product.items():
            for product_item in y_productlist:
                for token in discriptons_tokens:
                    if token == product_item:
                        if x_brand in Decision.keys():
                            Decision[x_brand].append(product_item)
                        else:
                            Decision[x_brand] = [product_item]
        # step 3 : check for keywords
        if len(vnd_keyword) >= 1:
            vnky = [i for i in vnd_keyword.keys()]
            discriptons_tokens = TextPreprocessing(discriptons, Notokenize=False)
            discriptons_tokens = set(discriptons_tokens)
            vend_scores = {}
            for i in vnky:
                vendcore = 0
                for ky in vnd_keyword[i]:
                    for token in discriptons_tokens:
                        if token == ky:
                            vendcore = vendcore + 1
                vend_scores[i] = vendcore

        # Decision
        finall_Decision = None
        if len(predict_brand) == 1:
            finall_Decision = predict_brand[0]
        else:
            maxlen = 1
            for pbrand in Decision.keys():
                if maxlen <= len(Decision[pbrand]):
                    maxlen = len(Decision[pbrand])
                    finall_Decision = pbrand
                    if pbrand in predict_brand:
                        break
                if (len(Decision.keys()) == 1):
                    finall_Decision = pbrand

        if len(vnd_keyword) >= 1:
            step3Decision = max(vend_scores, key=vend_scores.get)
            if step3Decision in predict_brand or step3Decision in Decision.keys():
                finall_Decision = step3Decision
            elif (predict_brand == None and len(Decision.keys()) == 0):
                finall_Decision = step3Decision
            if finall_Decision == None:
                finall_Decision = step3Decision

        # check for product
        predict_product = []
        try:
            for product_item_name in list(brand_product[finall_Decision]):
                for token in discriptons_tokens:
                    if token == product_item_name:
                        predict_product.append(product_item_name)
            if len(predict_product) == 0 :
                predict_product = None
        except:
            predict_product = None

        return [finall_Decision,predict_product]


    def show_ignores(self, ignore):
        # # show discriptons can not predict correct
        for i in ignore:
            discriptons = i[0]
            realvendor = VendorPreprocessing(i[1])
            print('Real  Vendor : ', realvendor, '\n')
            print(discriptons)

            # Decision
            Decision = {}
            predict_brand = []

            # step 1 : check for brands
            discriptons_tokens = VendorPreprocessing(discriptons, True)
            discriptons_tokens = set(discriptons_tokens)
            print('\n***step 1 check for brands***\n')
            for brand_name in list(self.brand_product.keys()):
                for token in discriptons_tokens:
                    if token == brand_name:
                        predict_brand.append(brand_name)
                        print(brand_name)

            # step 2 : check for Product
            discriptons_tokens = ProductPreprocessing(discriptons, True)
            discriptons_tokens = set(discriptons_tokens)
            print('\n***step 2 check for Product***\n')
            for x_brand, y_productlist in self.brand_product.items():
                for product_item in y_productlist:
                    for token in discriptons_tokens:
                        if token == product_item:
                            if x_brand in Decision.keys():
                                Decision[x_brand].append(product_item)
                            else:
                                Decision[x_brand] = [product_item]
            if len(Decision.keys()) > 0:
                for ky in Decision.keys():
                    print('Brand : ', ky, '\n Product : ', Decision[ky], '\n ----------------')
            # step 3 : check for keywords
            print('\n***step 3 check for keywords***\n')
            if len(self.vnd_keyword) >= 1:
                vnky = [i for i in self.vnd_keyword.keys()]
                discriptons_tokens = TextPreprocessing(discriptons, Notokenize=False)
                discriptons_tokens = set(discriptons_tokens)
                vend_scores = {}
                for i in vnky:
                    vendcore = 0
                    for ky in self.vnd_keyword[i]:
                        for token in discriptons_tokens:
                            if token == ky:
                                vendcore = vendcore + 1
                    vend_scores[i] = vendcore
                print(max(vend_scores, key=vend_scores.get), '\n')

                # Decision
                finall_Decision = None
                if len(predict_brand) == 1:
                    finall_Decision = predict_brand[0]
                else:
                    maxlen = 1
                    for pbrand in Decision.keys():
                        if maxlen <= len(Decision[pbrand]):
                            maxlen = len(Decision[pbrand])
                            finall_Decision = pbrand
                            if pbrand in predict_brand:
                                break
                    if (len(Decision.keys()) == 1):
                        finall_Decision = pbrand

                if len(self.vnd_keyword) >= 1:
                    step3Decision = max(vend_scores, key=vend_scores.get)
                    if step3Decision in predict_brand or step3Decision in Decision.keys():
                        finall_Decision = step3Decision
                    elif (predict_brand == None and len(Decision.keys()) == 0):
                        finall_Decision = step3Decision
                    if finall_Decision == None:
                        finall_Decision = step3Decision
                print('-------------Decision : {} -------------------------------------------------'.format(
                    finall_Decision))


    def update_None_Brands(self, chekdays=7):
        end = datetime.datetime.now()
        start = end - datetime.timedelta(days=chekdays)
        none_brands = self.Docs_Content.find({'$and': [{'product_id': None,'system_Brand_Prediction':None}, {'modified_date': {'$gte': start}}]})
        for item in none_brands:
            prdbrand = self.predictVndors(item['discriptons'])
            self.Docs_Content.update_one({'_id': item['_id']}, {"$set": {'system_Brand_Prediction': prdbrand}})
            print('system_Brand_Prediction for CVE ID :', item['cve_id'])
            prdbrand,prdproduct = self.predictVndors(item['discriptons'])
            self.Docs_Content.update_one({'_id': item['_id']}, {"$set": {'system_Brand_Prediction': prdbrand,
                                                                         'system_Product_Prediction': prdproduct
                                                                         }})
            print('system_Brand_Prediction for CVE ID :', item['cve_id'])

x=BrandPredictions()
x.update_None_Brands(120)