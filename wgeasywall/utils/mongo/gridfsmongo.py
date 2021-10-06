from re import finditer
import re
from warnings import catch_warnings


from wgeasywall.utils.mongo.core.db import get_db
import gridfs
from pathlib import Path

def getAllInFS(db,fs):
    database = get_db(db)
    if(type(database) == dict and 'ErrorCode' in database):
        return database
    try:
        fileSystem = gridfs.GridFS(database,collection=fs)
        result = fileSystem.list()
    except gridfs.errors.GridFSError as e:
        return {"ErrorCode":"601","ErrorMsg":"GridFS Download: {0}.".format(e)}

    return result

def delete(db,fs,fileID):

    database = get_db(db)
    try:
        fileSystem = gridfs.GridFS(database,collection=fs)
    except gridfs.errors.GridFSError as e:
        return {"ErrorCode":"601","ErrorMsg":"GridFS Download: {0}.".format(e)}
    
    try:
        fileSystem.delete(fileID)
    except gridfs.errors.GridFSError as e:
        return {"ErrorCode":"601","ErrorMsg":"GridFS Delete: {0}.".format(e)}
    
    return True

def deleteOldest(db,fs,fileName,count,maxItems):
        
    database = get_db(db)
    try:
        fileSystem = gridfs.GridFS(database,collection=fs)
    except gridfs.errors.GridFSError as e:
        return {"ErrorCode":"601","ErrorMsg":"GridFS Download: {0}.".format(e)}
    

    items = getAll(db=db,fs=fs,fileName=fileName)
    itemsLen = len((items))
    if ( itemsLen >= maxItems):
        iter = 1
        for item in items:
            if (iter > count):
                break
            try:
                fileSystem.delete(item._id)
            except gridfs.errors.GridFSError as e:
                return {"ErrorCode":"601","ErrorMsg":"GridFS Delete: {0}.".format(e)}
            iter = iter + 1

def findAbstract(db,fs,query):

    database = get_db(db)
    if(type(database) == dict and 'ErrorCode' in database):
        return database
    try:
        fileSystem = gridfs.GridFS(database,collection=fs)
        result = fileSystem.find(query)
    except gridfs.errors.GridFSError as e:
        return {"ErrorCode":"601","ErrorMsg":"GridFS Download: {0}.".format(e)}
    
    return list(result)


def getAll(db,fs,fileName):

    query = {"filename":fileName}
    return findAbstract(db,fs,query)


def getLatest(db,fs,fileName):

    database = get_db(db)
    if(type(database) == dict and 'ErrorCode' in database):
        return database
    try:
        fileSystem = gridfs.GridFS(database,collection=fs)
        result = fileSystem.get_last_version(filename=fileName)
    except gridfs.errors.GridFSError as e:
        return {"ErrorCode":"601","ErrorMsg":"GridFS Download: {0}.".format(e)}
    return result.read()

# TODO: If we need additional data to be stored for network file!
def upload(db,fs,filePath,uniqueName=None,additionalArgs=None):

    database = get_db(db)
    if(type(database) == dict and 'ErrorCode' in database):
        return database
    fileSystem = gridfs.GridFS(database,collection=fs)
    fileName = Path(filePath).name
    try:
        with open(filePath,'rb') as f:
            contents = f.read()
    except OSError:
        return {"ErrorCode":"600","ErrorMsg":"GridFS Upload : Could not open/read file: {0} to upload.".format(filePath)}
    if(uniqueName != None):
        dataID = fileSystem.put(contents,filename=fileName,uniqueName=uniqueName)
    else:
        dataID = fileSystem.put(contents,filename=fileName)
    return {"StatusCode":"200","DataID":dataID}

def uploadWithUniqueName(db,fs,filePath,uniqueName):
    database = get_db(db)
    if(type(database) == dict and 'ErrorCode' in database):
        return database
    fileSystem = gridfs.GridFS(database,collection=fs)
    fileName = Path(filePath).name
    try:
        with open(filePath,'rb') as f:
            contents = f.read()
    except OSError:
        return {"ErrorCode":"600","ErrorMsg":"GridFS Upload : Could not open/read file: {0} to upload.".format(filePath)}

    dataID = fileSystem.put(contents,filename=fileName,uniqueName=uniqueName)
    return {"StatusCode":"200","DataID":dataID}

def findWithFileNameUniqueName(db,fs,fileName,uniqueName):
    query = {'filename':fileName,'uniqueName':uniqueName}
    return findAbstract(db,fs,query=query)

def findWithUniqueName(db,fs,uniqueName):
    query = {'uniqueName':uniqueName}
    return findAbstract(db,fs,query=query)
