from wgeasywall.utils.mongo.core.connection import get_mongo_client 

def get_db(dbName):
    
    mongoClient = get_mongo_client()
    if(type(mongoClient) == dict and 'ErrorCode' in mongoClient):
        return mongoClient
    dblist = mongoClient.list_database_names()
    return mongoClient[dbName]