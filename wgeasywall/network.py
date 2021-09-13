from hashlib import new
from itertools import count
from pathlib import Path
from sys import path
from traceback import format_exception_only
from typing import Dict

import netaddr
from typer.main import Typer
from wgeasywall.utils.mongo.table.add import *
import typer
from wgeasywall.utils.parse.networkdefinition import *
from wgeasywall.utils.general.filedir import *
from wgeasywall.utils.general.configParser import get_configuration
from typing import Optional
from wgeasywall.utils.nacl.keyGenerate import *
from wgeasywall.utils.nacl.IPUtils import *
from wgeasywall.utils.mongo.gridfsmongo import *
from wgeasywall.utils.graphml.generate import *
import copy
from coolname import generate_slug
from wgeasywall.utils.wireguard.query import getInitilizedNetwork
from wgeasywall.utils.parse.diffdetector import *
from wgeasywall.utils.wireguard.query import *
from wgeasywall.view import network_definition
from wgeasywall.utils.mongo.core.collection import get_collection
app = typer.Typer()

def linter(networkDefiDict):

    LinterError = False
    CIDR = networkDefiDict['WGNet']['Subnet']
    ReservedRange = networkDefiDict['WGNet']['ReservedRange']

    # Check CIDR is Valid
    LinterCIDR = False
    validCIDR = isValidCIDR(CIDR)
    if type(validCIDR) == dict and 'ErrorCode' in validCIDR:
        typer.echo("ERROR : {0} is not the valid CIDR for subnet.".format(CIDR))
        LinterError = True
        LinterCIDR = True
    
    # It should retunr if the CIDR is not valid
    if (LinterCIDR):
        return LinterCIDR

    # Check is Reserved Range is Valid
    ReservedRangeList = ReservedRange.split("-")
    LinterReservedRange = False
    if (len(ReservedRangeList) != 2):
        typer.echo("ERROR : {0} is not the valid Reserved Range for the network.".format(ReservedRange))
        LinterError = True
    else:
        for IP in ReservedRangeList:
            validIP = isValidIP(IP)
            if type(validIP) == dict and 'ErrorCode' in validIP:
                typer.echo("ERROR : {0} is not the valid IP for reserved range.".format(IP))
                LinterError = True
                LinterReservedRange = True
            else:
                inCIDR = isIPinCIDR(CIDR,IP)
                if not inCIDR:
                    typer.echo("ERROR : {0} is not in the range CIDR {1} for reserved range.".format(IP,CIDR))
                    LinterError = True
    
    # Retrun if the reserved range is not valid
    if (LinterReservedRange):
        return LinterReservedRange
    
    # Server
    serverInfo = networkDefiDict['WGNet']['Server']
    ### Port
    validPort = isValidPort(serverInfo['Port'])
    if (type(validPort) == dict and 'ErrorCode' in validPort):
        typer.echo("ERROR: {0}".format(validPort['ErrorMsg']))
        LinterError = True
    ### Routes
    RoutesList = serverInfo['Routes'].split(',')
    for route in RoutesList:
        validtest = isValidCIDR(route)
        if (type(validtest) == dict and 'ErrorCode' in validtest):
            typer.echo("ERROR : {0} is not the valid CIDR for server routes.".format(route))
            LinterError = True
    ### Public IP
    serverPublicIP = serverInfo['PublicIPAddress']
    validtest = isValidIP(serverPublicIP)
    if (type(validtest) == dict and 'ErrorCode' in validtest):
            typer.echo("ERROR : {0} is not the valid server public IP.".format(serverPublicIP))
            LinterError = True
    
    ### Private IP
    validtest = isValidIP(serverInfo['IPAddress'])
    if (type(validtest) == dict and 'ErrorCode' in validtest):
        typer.echo("ERROR : {0} is not the valid server IP.".format(serverInfo['IPAddress']))
        LinterError = True
    
    # Client
    clientIPs = getClientsIP(networkDefiDict)
    clientsInNetwork = networkDefiDict['WGNet']['Clients']

    ## check clients with same name,hostname,valid route
    clientNames = []
    clientHostname = []

    clientRoute = {}

    for client in clientsInNetwork:
        clientNames.append(client['Name'])
        clientHostname.append(client['Hostname'])
        if ('Routes' in client):
            clientRoute[client['Name']] = client['Routes']

    ## Name
    for name in clientNames:
        if clientNames.count(name) > 1:
            typer.echo("ERROR: The client name of {0} has been used more than once.".format(name))
            LinterError = True
    ## hostname
    for hostname in clientHostname:
        if clientHostname.count(hostname) > 1:
            typer.echo("ERROR: The client hostname of {0} has been used more than once.".format(hostname))
            LinterError = True
    ## route
    for client,route in clientRoute.items():
        RoutesList = route.split(',')
        for route in RoutesList:
            validtest = isValidCIDR(route)
            if (type(validtest) == dict and 'ErrorCode' in validtest):
                typer.echo("ERROR : {0} is not the valid CIDR for client {1} routes.".format(route,client))
                LinterError = True
    

    ## Check if the client has valid IP
    LinterUnvalidIPs = False
    unValidIPs = {}
    for client,IP in clientIPs.items():
        if isValidIP(IP) != True:
            unValidIPs[client] = IP
    if len(unValidIPs) > 0 :
        typer.echo("ERROR: These clients have not valid IP addresses")
        for client,IP in unValidIPs.items():
            typer.echo("{0} with IP of {1}".format(client,IP))
        LinterError = True
        LinterUnvalidIPs = True
    
    # should return if we have a unvalid IP
    if (LinterUnvalidIPs) :
        return LinterUnvalidIPs


    ## Check if client has IP not in the range of CIDR
    notInNetworkIPs = {}
    for client,IP in clientIPs.items(): 
        if not isIPinCIDR(CIDR,IP):
            notInNetworkIPs[client] = IP
    if len(notInNetworkIPs) > 0:
        typer.echo("ERROR: These clients have IP addresses which are not in range of network {0}".format(CIDR))
        for client,IP in notInNetworkIPs.items():
            typer.echo("{0} with IP of {1}".format(client,IP))
        typer.echo("\n")
        LinterError = True

    ## Check if two clients have same IP Address
    duplicateIPs = findDuplicateIP(clientIPs)
    if len(duplicateIPs) > 0:
        typer.echo("ERROR: These clients have same IP addresses. Each client should have unique IP address.")
        for client,IP in duplicateIPs.items():
            typer.echo("{0} with IP of {1}".format(client,IP))
        typer.echo("\n")
        LinterError = True
    
    ## Check if the clients IP is range of rserved range
    unRengedIPs = {}
    for client,IP in clientIPs.items(): 
        if not isIPinRange(ReservedRangeList,IP):
            unRengedIPs[client] = IP
    if len(unRengedIPs) > 0:
        typer.echo("ERROR: These clients have IP addresses which are not in range of reserved IPs {0}".format(networkDefiDict['WGNet']['ReservedRange']))
        for client,IP in unRengedIPs.items():
            typer.echo("{0} with IP of {1}".format(client,IP))
        typer.echo("\n")
        LinterError = True
    
    return LinterError


@app.command()
def initilize(
networkFile: Path = typer.Option(...,"--network-file",help="The network definition file"),
keyDirectory : Optional[Path] = typer.Option(None,"--keys-dir",help="The directory which contains clients public key for uncontrolled clients"),
graphName: str = typer.Option(None,"--graph-file-name",help="The generated GraphML file name. Default: Network Name")
):

    """
    Initilize WireGuard Networks from the Network Definition file
    """
    
    if not networkFile.is_file():
        typer.echo("ERROR: Network Definition file can't be found!",err=True)
        raise typer.Exit(code=1)
    
    networkDefiDict = get_configuration(networkFile)

    if (type(Dict) and 'ErrorCode' in networkDefiDict):

        typer.echo("ERORR: Can't read Network Definition file.  {0}".format(networkDefiDict['ErrorMsg']))
        raise typer.Exit(code=1)

    networkName = networkDefiDict['WGNet']['Name']
    findNetworkQuery = {"_id": get_sha2(networkName)}
    queryNetwork = query_abstract(database_name='Networks',table_name='init',query=findNetworkQuery)
    if (type(queryNetwork) == dict and 'ErrorCode' in queryNetwork):
        return queryNetwork
    
    networkInit = list(queryNetwork['Enteries'])
    if ( len(list(networkInit)) > 0 and networkInit[0]['initilized'] ):
        typer.echo("ERROR: The network {0} was initilized and can't be initilized again.".format(networkName))
        raise typer.Exit(code=1)

    # Lint
    LintError = linter(networkDefiDict)
    if (LintError):
        typer.echo("Abort!")
        raise typer.Exit(code=1)

    # Check if the network subnet has overlap with others
    CIDR = networkDefiDict['WGNet']['Subnet']
    
    clientsControlLevel = getClientBasedControlLevel(networkDefiDict)

    networkDefiDictNoTouch = copy.deepcopy(networkDefiDict)

    if (len(clientsControlLevel['Uncontrolled']) > 0 and keyDirectory == None):
        typer.echo("ERORR: There is more than one uncontrolled client in the network definition, keys directory should be specified!")
        raise typer.Exit(code=1)

    # Network Part
    if (graphName == None):
        graphName = networkName
    
    ReservedRange = networkDefiDict['WGNet']['ReservedRange'].split('-')
    ReservedRangeIP = netaddr.IPRange(ReservedRange[0],ReservedRange[1])
    CIDRInfo = getCIDRInfo(CIDR)

    serverInfo = networkDefiDict['WGNet']['Server']

    CIDRData = {
        '_id': get_sha2(CIDR),
        'cidr': CIDR,
        'mask': str(CIDRInfo['Mask']),
        'size': CIDRInfo['Size'],
        'firstIP': str(CIDRInfo['FirstIP']),
        'lastIP': str(CIDRInfo['LastIP']),
        # 'nextIP': str(CIDRInfo['FirstIP']), 
        'serverIP': serverInfo['IPAddress'],
        'reservedRange': networkDefiDict['WGNet']['ReservedRange']
    }
    freeIPLIST = []
    for ip in CIDRInfo['CIDR']:

        if(ip == CIDRInfo['CIDR'].network or ip == CIDRInfo['CIDR'].broadcast or str(ip) == serverInfo['IPAddress']):
            continue
        
        data = {}
        data['_id'] = get_sha2(str(ip))
        data['IP'] = str(ip)
        if (ip in ReservedRangeIP):
            data['static'] = 'True'
        else:
            data['static'] = 'False'

        freeIPLIST.append(data)
    

    # Key Part
    allClients = []

    for client in clientsControlLevel['Uncontrolled']:
        clientKeyPath = "{0}/{1}.pb".format(keyDirectory,client['Name'])
        key = getFile(clientKeyPath)

        if (type(key) == dict):
            typer.echo("ERROR: The key file '{0}.pub' for client: {0} can't be found!".format(client))
            raise typer.Exit(code=1)
        client['PublicKey'] = key
        client['PrivateKey'] = ""

    for client in clientsControlLevel['Controlled']:
        clientKey = generateEDKeyPairs()
        client['PublicKey'] = clientKey[1]
        client['PrivateKey'] = clientKey[0]

    allClients =  clientsControlLevel['Controlled'] + clientsControlLevel['Uncontrolled']
    
    # Server 
    serverKey = generateEDKeyPairs()
    serverInfo['_id'] = get_sha2(serverInfo['Name'])
    serverInfo['PublicKey'] = serverKey[1]
    serverInfo['PrivateKey'] = serverKey[0]
    addResult = add_entry_one(database_name=networkName,table_name='server',data=serverInfo)
    if (type(addResult) == dict and 'ErrorCode' in addResult):
        typer.echo("ERORR: Can't connect to database and initilize network")
        raise typer.Exit(code=1)
    
    # ADD ALL to DATABASE
    add_entry_multiple(database_name=networkName,table_name='freeIP',data=freeIPLIST)
    addResult = add_entry_one(database_name=networkName,table_name='subnet',data=CIDRData)
    if (type(addResult) == dict and 'ErrorCode' in addResult):
        typer.echo("ERORR: Can't connect to database and initilize network")
        raise typer.Exit(code=1)
    
    typer.echo("IP-Assigner setup done.")

    for client in allClients:
        client['_id'] = get_sha2(client['Name'])
        if(client['IPAddress'] == ""):
            client['IPAddress'] = requestIP(networkName,client['Name'])
        else:
            client['IPAddress'] = requestIP(networkName,client['Name'],IP=client['IPAddress'])
    
    add_entry_multiple(database_name=networkName,table_name='clients',data=allClients)

    allClients2addGraph = copy.deepcopy(allClients)

    for client in allClients2addGraph:
        client.pop('_id')
        client.pop('PublicKey')
        client.pop('PrivateKey')

    g = pyyed.Graph()
    addNodeCustomProperties(g)
    allGroupObject = generateGroupsObject(g,networkDefiDictNoTouch)
    generateGraph(allGroupObject,networkDefiDictNoTouch,g,allClients2addGraph,graphName)
    add_entry_one(database_name='Networks',table_name='init',data={'_id':get_sha2(networkName),'network':networkName,'initilized':True, 'cidr':CIDR})

    # Upload Network File to DataBase
    networkTempPath = create_temporary_copy(path=networkFile,networkName="{0}.yaml".format(networkName))
    netdefUniqueName = generate_slug(2)
    upload(db=networkName,fs='netdef',filePath=networkTempPath,uniqueName=netdefUniqueName)
    os.remove(networkTempPath)
    typer.echo("The provided Network definition is added to the database with the unique name of {0}. You can use this name to access the network definition.".format(netdefUniqueName))
    # TODO: Store GraphML to the database ?


@app.command()
def update(
    networkFile: Path = typer.Option(...,"--network-file",help="The new network definition file"),
):
    
    if not networkFile.is_file():
        typer.echo("ERROR: Network Definition file can't be found!",err=True)
        raise typer.Exit(code=1)
    
    networkDefiDict = get_configuration(networkFile)

    if (type(Dict) and 'ErrorCode' in networkDefiDict):

        typer.echo("ERORR: Can't read Network Definition file.  {0}".format(networkDefiDict['ErrorMsg']))
        raise typer.Exit(code=1)

    networkName = networkDefiDict['WGNet']['Name']

    isInitilized = isNetworkInitilized(networkName)
    if(type(isInitilized) == dict):
        if(isInitilized['ErrorCode'] == '900'):
            typer.echo(isInitilized['ErrorMsg'])
            typer.echo("Can't update the network {0} which is not initialized yet".format(networkName))
            raise typer.Exit(code=1)
        else:
            typer.echo("ERROR: Can't connect to database. {0}".format(isInitilized))
            raise typer.Exit(code=1)

    # GET OLD Network Definition
    query = {'filename':'{0}.yaml'.format(networkName)}
    files = findAbstract(networkName,'netdef',query=query)
    oldNetworkDefiDict = yaml.safe_load(files[0].read().decode())
    

    # Detect Difference between OLD and NEW in Server Settings 

    serverInfo = networkDefiDict['WGNet']['Server']
    oldServerInfo = oldNetworkDefiDict['WGNet']['Server']

    ## Lint
    LintError = linter(networkDefiDict)
    ### server name and hostname
    if (serverInfo['Name'] != oldServerInfo['Name']):
        typer.echo("ERROR: The server's name can't be updated after initialization.")
        typer.echo("Update the server's name in the provided network defintion to {0} and re-run command.".format(oldServerInfo['Name']))
        LintError = True
    if (serverInfo['Hostname'] != oldServerInfo['Hostname']):
        typer.echo("ERROR: The server's hostname can't be updated after initialization.")
        typer.echo("Update the server's hostname in the provided network defintion to {0} and re-run command.".format(oldServerInfo['Name']))
        LintError = True
    ### ALL
    if (LintError):
        typer.echo("Update Abort.")
        raise typer.Exit(code=1)
    
    ## Detect Changes 
    isChangeServerPort = (False,"","")
    if (serverInfo['Port'] != oldServerInfo['Port']):
        typer.echo("The server's port will be updated form {0} to {1} .".format(oldServerInfo['Port'],serverInfo['Port']))
        isChangeServerPort = (True,serverInfo['Port'],oldServerInfo['Port'])
    
    ### Routes
    isChangeServerRoutes = (False,"","")
    if (serverInfo['Routes'] != oldServerInfo['Routes']):
        typer.echo("The server's routes will be updated form {0} to {1} .".format(oldServerInfo['Routes'],serverInfo['Routes']))
        isChangeServerRoutes = (True,serverInfo['Routes'],oldServerInfo['Routes'])

    ### Public IP
    isChangeServerPublicIP = (False,"","")
    if (serverInfo['PublicIPAddress'] != oldServerInfo['PublicIPAddress']):
        typer.echo("The server's public IP address will be updated form {0} to {1} .".format(oldServerInfo['PublicIPAddress'],serverInfo['PublicIPAddress']))
        isChangeServerPublicIP = (False,serverInfo['PublicIPAddress'],oldServerInfo['PublicIPAddress'])

    ### Private IP
    isChangedServerIP = (False,"","")
    if (serverInfo['IPAddress'] != oldServerInfo['IPAddress']):
        typer.echo("The server's IP address will be updated form {0} to {1} .".format(oldServerInfo['IPAddress'],serverInfo['IPAddress']))
        isChangedServerIP = (False,serverInfo['IPAddress'],oldServerInfo['IPAddress'])


    
    # Detect Difference between OLD and NEW in Network Settings
    networkSettingsDiff = getNetDiff(networkDefiDict,oldNetworkDefiDict,networkName,'Net')['values_changed']

    isChangeSubnet = (False,"","")

    for item in networkSettingsDiff['Items']:
        
        if (item['AttributeChanged'] == 'ReservedRange'):
            typer.echo("ERROR: The reserved range is fixed and can't be changed after initialization.")
            typer.echo("Initialized value : {0} ".format(item['ObjectOldInfo']['ReservedRange']))
            typer.echo("New value : {0} ".format(item['ObjectNewInfo']['ReservedRange']))
            typer.echo("Please update the reserved range to initialized value and re-run command again")
            raise typer.Exit(code=1)

        if (item['AttributeChanged'] == 'Subnet'):
            newSubnet = item['ObjectNewInfo']['Subnet']
            oldSubnet = item['ObjectOldInfo']['Subnet']

            if not isLargerCIDR(newSubnet,oldSubnet):
                typer.echo("ERROR: The new subnet {0} is not supernet of old subnet {1}.".format(newSubnet,oldSubnet))
                typer.echo("The new subnet should be larger than old subnet")
                typer.echo("Update Abort.")
                raise typer.Exit(code=1)
            else:
                typer.echo("The network subnet will be updated from {0} to {1}.".format(oldSubnet,newSubnet))
                isChangeSubnet = (True,newSubnet,oldSubnet)

    ## Check if subnet is updated or not
    if (isChangeSubnet[0]):

        ### Update subnet
        newCIDR = isChangeSubnet[1]
        oldCIDR = isChangeSubnet[2]

        serverInfo = networkDefiDict['WGNet']['Server']

        additionalIPs = subtractCIDR(newCIDR,oldCIDR)
        
        newCIDRInfo = getCIDRInfo(newCIDR)

        #### Update init table
        networkQuery = {"_id":get_sha2(networkName)}
        newInitValue = { "$set": { "cidr": newCIDR } }
        resultUpadte = update_one_abstract(database_name='Networks',table_name='init',query=networkQuery,newvalue=newInitValue)
        if (type(resultUpadte) == dict and 'ErrorCode' in resultUpadte):
            typer.echo("ERORR: Can't connect to database and initilize network")
            raise typer.Exit(code=1)
        
        #### Update Subnet table
        CIDRData = {
        '_id': get_sha2(newCIDR),
        'cidr': newCIDR,
        'mask': str(newCIDRInfo['Mask']),
        'size': newCIDRInfo['Size'],
        'firstIP': str(newCIDRInfo['FirstIP']),
        'lastIP': str(newCIDRInfo['LastIP']),
        'serverIP': serverInfo['IPAddress'],
        'reservedRange': networkDefiDict['WGNet']['ReservedRange']
         }
        
        subnetTable = get_collection(db_name=networkName,collection_name='subnet')
        if (type(subnetTable) == dict and 'ErrorCode' in subnetTable):
            typer.echo("ERROR: Can't connect to database. {0}".format(subnetTable))
            raise typer.Exit(code=1)
        subnetTable.drop()
        add_entry_one(database_name=networkName,table_name='subnet',data=CIDRData)

        #### Update FreeIP Table
        lastIPofOldSubnet = ipaddress.IPv4Network(oldCIDR)[-1]
        additionalIPs.append(ipaddress.IPv4Address(lastIPofOldSubnet))
        additionalIPs= sorted(additionalIPs)
        del additionalIPs[-1] # remove broadcast IP

        freeIPLIST = []
        for ip in additionalIPs:
            data = {}
            data['_id'] = get_sha2(str(ip))
            data['IP'] = str(ip)
            data['static'] = 'False'

            freeIPLIST.append(data)
        
        add_entry_multiple(database_name=networkName,table_name='freeIP',data=freeIPLIST)
        
        



    
