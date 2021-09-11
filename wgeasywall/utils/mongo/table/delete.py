from wgeasywall.utils.mongo.core import collection

def delete_abstract_one(database_name,table_name,query):

    table = collection.get_collection(database_name,table_name)
    if(type(table) == dict and 'ErrorCode' in table):
        return table
    try:
        result = table.delete_one(query)
    except Exception as e:
        return {"ErrorCode":"700","ErrorMsg":e}
    else:
        return {"StatusCode":"200","Response":result}

def delete_abstract_multiple(database_name,table_name,query):

    table = collection.get_collection(database_name,table_name)
    if(type(table) == dict and 'ErrorCode' in table):
        return table
    try:
        result = table.delete_many(query)
    except Exception as e:
        return {"ErrorCode":"700","ErrorMsg":e}
    else:
        return {"StatusCode":"200","Response":result}


# def delete_user_by_email(database_name,table_name,email):

#     emailQuery = {"email":str(email)}

#     result = delete_abstract_one(database_name,table_name,emailQuery)
#     return result