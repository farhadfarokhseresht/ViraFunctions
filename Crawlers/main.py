import NvdCrawler, Brand_Prediction, Cwe_Prediction, UbuntuCrawler, PostgresqlCrawler, QualcommCrawler
import MicrosoftCrawler, HuaweiCrawler, F5Crawler
import schedule
import time


def Prediction_schedule():
    brand_prd_obj = Brand_Prediction.BrandPredictions()
    cwe_prd_obj = Cwe_Prediction.Cwe_Prediction()
    brand_prd_obj.update_None_Brands(chekdays=120)
    cwe_prd_obj.update_None_CWE(chekdays=120)


# NVD
def NvdCrawler_schedule():
    NvdCrawler_OBJECT = NvdCrawler.NvdCrawler()
    NvdCrawler_OBJECT.getcve(chekdays=1)


# Ubuntu
def UbuntuCrawler_schedule():
    UbuntuCrawler_OBJECT = UbuntuCrawler.UbuntuCrawler()
    UbuntuCrawler_OBJECT.getcve()


# Postgresql
def PostgresqlCrawler_schedule():
    PostgresqlCrawler_OBJECT = PostgresqlCrawler.PostgresqlCrawler()
    PostgresqlCrawler_OBJECT.getcve()


# QualcommCrawler
def QualcommCrawler_schedule():
    QualcommCrawler_OBJECT = QualcommCrawler.QualcommCrawler()
    QualcommCrawler_OBJECT.getcve()


# MicrosoftCrawler
def MicrosoftCrawler_schedule():
    MicrosoftCrawler_OBJECT = MicrosoftCrawler.MicrosoftCrawler()
    MicrosoftCrawler_OBJECT.getcve()


# HuaweiCrawler
def HuaweiCrawler_schedule():
    HuaweiCrawler_OBJECT = HuaweiCrawler.HuaweiCrawler()
    HuaweiCrawler_OBJECT.getcve()


# F5Crawler
def F5Crawler_schedule():
    F5Crawler_OBJECT = F5Crawler.F5Crawler()
    F5Crawler_OBJECT.getcve()


def mainfunctions():
    try:
        NvdCrawler_schedule()
    except:
        pass
    time.sleep(1)
    try:
        UbuntuCrawler_schedule()
    except:
        pass
    time.sleep(1)
    try:
        PostgresqlCrawler_schedule()
    except:
        pass
    time.sleep(1)
    try:
        QualcommCrawler_schedule()
    except:
        pass
    time.sleep(1)

    try:
        MicrosoftCrawler_schedule()
    except:
        pass
    time.sleep(1)

    try:
        HuaweiCrawler_schedule()
    except:
        pass
    time.sleep(1)

    try:
        F5Crawler_schedule()
    except:
        pass
    time.sleep(1)


schedule.every(1).minutes.do(mainfunctions)
schedule.every(1).days.do(Prediction_schedule)

while True:
    schedule.run_pending()
    time.sleep(1)
