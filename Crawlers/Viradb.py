import pymongo

class Viradb():
    my_client = pymongo.MongoClient('mongodb://tanha:tanha1ubuntu@37.32.24.36', 27017)
    # my_client = pymongo.MongoClient('localhost', 27017)
    Viradb = my_client.Viradb
    Score = Viradb.scores
    Docs_Content = Viradb.docs_contents
    CWE = Viradb.cwes
    Brand = Viradb.brands
    Product = Viradb.products

    # Docs_Content.delete_many({})
    # Score.delete_many({})
 
