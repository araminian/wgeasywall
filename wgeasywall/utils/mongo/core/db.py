import donna25519
from wgeasywall.utils.mongo.core.connection import get_mongo_client 

def get_db(dbName):
    
    mongoClient = get_mongo_client()
    if(type(mongoClient) == dict and 'ErrorCode' in mongoClient):
        return mongoClient
    dblist = mongoClient.list_database_names()
    return mongoClient[dbName]

def copy_db(srcName,targetName):
    
    collections = ['clients','freeIP','leasedIP','server','subnet']
    srcDB = get_db(srcName)
    dstDB = get_db(targetName)

    for collection in collections:
        srcCollectionObject = srcDB[collection]
        dstCollectionObject = dstDB[collection]
        for data in srcCollectionObject.find():
            try:
                dstCollectionObject.insert(data)
            except:
                return {'ErrorCode':'710','ErrorMsg':"Can't copy."}
        
def delete_db(dbName):
    mongoClient = get_mongo_client()
    mongoClient.drop_database(dbName)



