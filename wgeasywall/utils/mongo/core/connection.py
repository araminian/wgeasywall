import pymongo
import urllib
from wgeasywall.vars import get_mongo_configuration_location
from wgeasywall.utils.general.configParser import get_configuration

def get_mongo_configuration():

    mongoConfigPath = get_mongo_configuration_location()

    mongoConfig = get_configuration(mongoConfigPath)

    if('ErrorCode' in mongoConfig):
        return mongoConfig

    config = {}
    config['WG_MONGO_ADDRESS'] = mongoConfig['MongoDB']['mongo_address']
    config['WG_MONGO_USER'] = mongoConfig['MongoDB']['mongo_user']
    config['WG_MONGO_PASSWORD'] = mongoConfig['MongoDB']['mongo_password']
    
    return config

def get_mongo_client():
    mongoConfiguration = get_mongo_configuration()
    if('ErrorCode' in mongoConfiguration):
        return mongoConfiguration
    username = urllib.parse.quote_plus(mongoConfiguration['WG_MONGO_USER'])
    password = urllib.parse.quote_plus(mongoConfiguration['WG_MONGO_PASSWORD'])
    serverAddress = mongoConfiguration['WG_MONGO_ADDRESS']
    accessURL = "mongodb://{0}:{1}@{2}".format(username,password,serverAddress)
    client = pymongo.MongoClient(accessURL)
    # https://pymongo.readthedocs.io/en/stable/migrate-to-pymongo3.html#mongoclient-connects-asynchronously
    try:
        DBs = client.list_database_names()
    except pymongo.errors.ConnectionFailure as e:
        Error = {"ErrorCode":"700","ErrorMsg":e}
        return Error
    except pymongo.errors.ServerSelectionTimeoutError as e:
        Error = {"ErrorCode":"700","ErrorMsg":e}
        return Error
    except pymongo.errors.OperationFailure as e:
        Error = {"ErrorCode":"700","ErrorMsg":e}
        return Error
    except :
        Error = {"ErrorCode":"700","ErrorMsg":"Other Errors"}
    else:
        return client