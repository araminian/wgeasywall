
def getClientBasedControlLevel(networkDict):

    """
    Catagorize clients based on control level

    Example: getClientBasedControlLevel('WGNet1',netdef)
    """
    controlledClients = []
    uncontrolledClients = []
    clientsInNetwork = getClients(networkDict)
    
    for client in clientsInNetwork:
        
        if (client['UnderControl'] == 'True'):
            controlledClients.append(client) #client['Name']
        elif (client['UnderControl'] == 'False'):
            uncontrolledClients.append(client)
    
    return {'Controlled':controlledClients,'Uncontrolled':uncontrolledClients}

def getClients(networkDict):

    """
    Get Clients in a Network
    """
    server = networkDict['WGNet']['Server']
    severRoute = server['Routes']
    

    clientsInNetwork = networkDict['WGNet']['Clients']
    for client in clientsInNetwork:
        # If client is not member of any group, its group should be ''
        # if not 'Group' in  client:
        #     client['Group'] = ""
        
        # If client has no defined route , it should inherit from Server
        if not 'Routes' in client:
            client['Routes'] = severRoute
        
        if not 'IPAddress' in client:
            client['IPAddress'] = ""
        
    return clientsInNetwork

def getServer(networkDict):
    """
    Get Server information in a specific network
    """

    return networkDict['WGNet']['Server']

def getNetworkResources(networkDict):
    """
    Get Network Resources
    """

    return networkDict['NetworkResources']

def getClientsIP(networkDict):

    clientsInNetwork = getClients(networkDict)
    clientsIPs = {}
    for client in clientsInNetwork:
        
        if client['IPAddress'] != "":
            clientsIPs[client['Name']] = client['IPAddress']
    return clientsIPs

