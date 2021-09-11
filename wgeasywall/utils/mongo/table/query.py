from wgeasywall.utils.mongo.core import collection

def query_abstract(database_name,table_name,query):

    table = collection.get_collection(database_name,table_name)
    if(type(table) == dict and 'ErrorCode' in table):
        return table
    try:
        entries = table.find(query)
    except Exception as e:
        return {"ErrorCode":"700","ErrorMsg":e}
    else:
        return {"StatusCode":"200","Enteries":entries}


# def query_user_by_email(database_name,table_name,email):

#     emailQuery = {"email":str(email)}

#     entries = query_abstract(database_name,table_name,emailQuery)
#     return entries