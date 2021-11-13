from wgeasywall.utils.mongo.table.get import *
from wgeasywall.utils.mongo.table.query import *
from wgeasywall.utils.general.general import *


def getClientsControlLevel(clients):
    
    controlled = []
    noControlled = []

    for client in clients:
        if (client['UnderControl'] == 'True'):
            controlled.append(client)
        elif (client['UnderControl'] == 'False'):
            noControlled.append(client)
    return (controlled,noControlled)


def getInitializedNetwork():

    network = get_all_entries(database_name='Networks',table_name='init')
    if (type(network) == dict and 'ErrorCode' in network):
        return network
    networkInit = list(network['Enteries'])

    return networkInit



def isNetworkInitialized(networkName):
    queryNetwork = {"_id": get_sha2(networkName)}
    network = query_abstract(database_name='Networks',table_name='init',query=queryNetwork)

    if (type(network) == dict and 'ErrorCode' in network):
        return network

    networkInit = list(network['Enteries'])

    if (len(networkInit) == 0 ):
        return {'ErrorCode':'900','ErrorMsg':"The network {0} is not initialized.".format(networkName)}

    return True

def getClients(networkName):

    isInitialized = isNetworkInitialized(networkName)
    if(type(isInitialized) == dict):
        return isInitialized
    
    clients = get_all_entries(database_name=networkName,table_name='clients')
    if (type(clients) == dict and 'ErrorCode' in clients):
        return clients

    clientList = list(clients['Enteries'])

    return clientList

def getServer(networkName):

    isInitialized = isNetworkInitialized(networkName)
    if(type(isInitialized) == dict):
        return isInitialized

    server = get_all_entries(database_name=networkName,table_name='server')
    if (type(server) == dict and 'ErrorCode' in server):
        return server

    serverObject = list(server['Enteries'])[0]
    return serverObject

def getSubnet(networkName):
    
    isInitialized = isNetworkInitialized(networkName)
    if(type(isInitialized) == dict):
        return isInitialized
    
    subnet = get_all_entries(database_name=networkName,table_name='subnet')
    if (type(subnet) == dict and 'ErrorCode' in subnet):
        return subnet

    subnetObject = list(subnet['Enteries'])[0]
    return subnetObject