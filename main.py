from Crawlers import NvdCrawler, UbuntuCrawler, PostgresqlCrawler, HuaweiCrawler
from Crawlers import F5Crawler, HuaweiCrawler, MicrosoftCrawler, QualcommCrawler
from Server_Functions import Brand_Prediction#, Cwe_Prediction
import threading
import schedule


def Prediction_schedule():
    brand_prd_obj = Brand_Prediction.BrandPredictions()
    # cwe_prd_obj = Cwe_Prediction.Cwe_Prediction()
    brand_prd_obj.update_None_Brands(chekdays=120)
    # cwe_prd_obj.update_None_CWE(chekdays=120)



# NVD
def NvdCrawler_schedule():
    NvdCrawler_OBJECT = NvdCrawler.NvdCrawler()
    NvdCrawler_OBJECT.getcve(chekdays=120)

# Ubuntu
# def UbuntuCrawler_schedule():
#     UbuntuCrawler_OBJECT = UbuntuCrawler.UbuntuCrawler()
#     UbuntuCrawler_OBJECT.getcve()


# Postgresql
# def PostgresqlCrawler_schedule():
#     PostgresqlCrawler_OBJECT = PostgresqlCrawler.PostgresqlCrawler()
#     PostgresqlCrawler_OBJECT.getcve()


# QualcommCrawler
# def QualcommCrawler_schedule():
#     QualcommCrawler_OBJECT = QualcommCrawler.QualcommCrawler()
#     QualcommCrawler_OBJECT.getcve()


# MicrosoftCrawler
# def MicrosoftCrawler_schedule():
#     MicrosoftCrawler_OBJECT = MicrosoftCrawler.MicrosoftCrawler()
#     MicrosoftCrawler_OBJECT.getcve()


# HuaweiCrawler
# def HuaweiCrawler_schedule():
#     HuaweiCrawler_OBJECT = HuaweiCrawler.HuaweiCrawler()
#     HuaweiCrawler_OBJECT.getcve()


# F5Crawler
# def F5Crawler_schedule():
#     F5Crawler_OBJECT = F5Crawler.F5Crawler()
#     F5Crawler_OBJECT.getcve()


# schedule.every(1).minutes.do(NvdCrawler_schedule)
# schedule.every(10).minutes.do(UbuntuCrawler_schedule)
# schedule.every(15).minutes.do(PostgresqlCrawler_schedule)
# schedule.every(20).minutes.do(QualcommCrawler_schedule)
# schedule.every(25).minutes.do(MicrosoftCrawler_schedule)
# schedule.every(30).minutes.do(F5Crawler_schedule)
# schedule.every(1).days.do(Prediction_schedule)


NvdCrawler_threading = threading.Thread(target=NvdCrawler_schedule)
# UbuntuCrawler_threading = threading.Thread(target=UbuntuCrawler_schedule)
# PostgresqlCrawler_threading = threading.Thread(target=PostgresqlCrawler_schedule)
# QualcommCrawler_threading = threading.Thread(target=QualcommCrawler_schedule)
# MicrosoftCrawler_threading = threading.Thread(target=MicrosoftCrawler_schedule)
# F5Crawler_threading = threading.Thread(target=F5Crawler_schedule)
Prediction_threading = threading.Thread(target=Prediction_schedule)

# NvdCrawler_threading.start()
# UbuntuCrawler_threading.start()
# PostgresqlCrawler_threading.start()
# QualcommCrawler_threading.start()
# MicrosoftCrawler_threading.start()
# F5Crawler_threading.start()
Prediction_threading.start()
