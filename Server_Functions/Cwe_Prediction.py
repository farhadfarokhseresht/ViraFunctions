import nltk
import string
from nltk.tokenize import word_tokenize
from nltk.stem import PorterStemmer
from nltk.stem import WordNetLemmatizer
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.feature_extraction.text import TfidfTransformer
import pymongo
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.linear_model import SGDClassifier
from sklearn.pipeline import Pipeline
from sklearn.metrics import accuracy_score
import pickle
import datetime
import os
import glob

# TextPreprocessing
porter_stemmer = PorterStemmer()
wordnet_lemmatizer = WordNetLemmatizer()


def TextPreprocessing(text, method=False, Notokenize=True):
    # Punctuation Removal
    preproces_txt = text
    preproces_txt = "".join([i for i in preproces_txt if i not in string.punctuation + '0123456789'])
    # Lowering the text
    preproces_txt = preproces_txt.lower()
    # Tokenization
    preproces_txt = word_tokenize(preproces_txt)
    # Stop word removal
    stopwords = nltk.corpus.stopwords.words('english')
    preproces_txt = [i for i in preproces_txt if i not in stopwords]
    # remove words less than three letters
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


class Cwe_Prediction():
    # data base
    my_client = pymongo.MongoClient('localhost', 27017)
    Viradb = my_client.Viradb2
   #
    Score = Viradb.scores
    Docs_Content = Viradb.docs_contents
    CWE = Viradb.cwes
    Brand = Viradb.brands
    Product = Viradb.products
    now = datetime.datetime.now()

    sgd = Pipeline([('vect', CountVectorizer()),
                    ('tfidf', TfidfTransformer()),
                    ('clf', SGDClassifier(loss='modified_huber', penalty='elasticnet', alpha=1e-3, random_state=42,
                                          max_iter=1000, tol=1e-5)),
                    ])
    path = os.getcwd()
    sav_files = glob.glob(os.path.join(path, "*.sav"))
    # save the model to disk
    filename = 'SGDClassifier_model_{}_{}.sav'.format(str(now.month), str(now.day))
    try:
        # load the model from disk
        sgd = pickle.load(open(filename, 'rb'))
    except:
        cwe_meta_data = {}
        cwe_id_name = {}
        cwe_obj = CWE.find({})
        for cwe in cwe_obj:
            cweid = cwe['cwe_id']
            try:
                cwe_title_latin = cwe['cwe_title_latin']
            except:
                cwe_title_latin = ''
            try:
                cwe_detail = cwe['cwe_detail']
            except:
                cwe_detail = ''
            cwe_detail = cwe_title_latin + cwe_detail
            cwe_meta_data[str(cwe['_id'])] = cwe_detail
            cwe_id_name[str(cwe['_id'])] = cweid
        # Discripton vis CWE
        Model_data = []
        for obj in Docs_Content.find({'cwe_id': {'$ne': None}}):
            dis = obj['discriptons']
            dis = TextPreprocessing(dis)
            try:
                if len(obj['cwe_id']) >= 1:
                    for cwe in obj['cwe_id']:
                        Model_data.append([cwe_id_name[str(cwe)], dis + cwe_meta_data[str(cwe)]])
            except:
                pass
        Model_data = pd.DataFrame(Model_data, columns=['cwe', 'text'])

        try:
            sgd.fit(Model_data.text, Model_data.cwe)
            for f in sav_files:
                os.remove(f)
            pickle.dump(sgd, open(filename, 'wb'))
        except:
            sgd = pickle.load(open(sav_files[0], 'rb'))

    def predict_cwe(self, Discripton):
     Discripton = TextPreprocessing(Discripton)
     return self.sgd.predict([Discripton])

    def update_None_CWE(self, chekdays=7):
        end = datetime.datetime.now()
        start = end - datetime.timedelta(days=chekdays)
        none_brands = self.Docs_Content.find({'$and': [{'cwe_id': None}, {'modified_date': {'$gte': start}}]})
        for item in none_brands:
            prdcwe = self.predict_cwe(item['discriptons'])[0]
            self.Docs_Content.update_one({'_id': item['_id']}, {"$set": {'system_Cwe_Prediction': prdcwe}})



x = Cwe_Prediction.update_None_CWE()