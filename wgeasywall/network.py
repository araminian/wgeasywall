from hashlib import new
from itertools import count
from pathlib import Path
from sys import path
from traceback import format_exception_only
from typing import Dict
from wgeasywall.utils.mongo.core.db import copy_db, delete_db

import netaddr
from pymongo import database
from pymongo.results import UpdateResult
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
import copy , string
from coolname import generate_slug
from wgeasywall.utils.parse.diffdetector import *
from wgeasywall.utils.wireguard.query import *
from wgeasywall.view import network_definition, server, subnet_report
from wgeasywall.utils.mongo.core.collection import get_collection
from wgeasywall.utils.graphml.update import *
app = typer.Typer()
from python_hosts import Hosts, HostsEntry


def linter(networkDefiDict,WGMode):

    LinterError = False
    if(WGMode):
        CIDR = networkDefiDict['WGNet']['Subnet']
        ReservedRange = networkDefiDict['WGNet']['ReservedRange']

        # Check CIDR is Valid
        LinterCIDR = False
        validCIDR = isValidCIDR(CIDR)
        if type(validCIDR) == dict and 'ErrorCode' in validCIDR:
            typer.echo("ERROR : {0} is not the valid CIDR for subnet.".format(CIDR),err=True)
            LinterError = True
            LinterCIDR = True
        
        # It should retunr if the CIDR is not valid
        if (LinterCIDR):
            return LinterCIDR

        # Check is Reserved Range is Valid
        ReservedRangeList = ReservedRange.split("-")
        LinterReservedRange = False
        if (len(ReservedRangeList) != 2):
            typer.echo("ERROR : {0} is not the valid Reserved Range for the network.".format(ReservedRange),err=True)
            LinterError = True
        else:
            for IP in ReservedRangeList:
                validIP = isValidIP(IP)
                if type(validIP) == dict and 'ErrorCode' in validIP:
                    typer.echo("ERROR : {0} is not the valid IP for reserved range.".format(IP),err=True)
                    LinterError = True
                    LinterReservedRange = True
                else:
                    inCIDR = isIPinCIDR(CIDR,IP)
                    if not inCIDR:
                        typer.echo("ERROR : {0} is not in the range CIDR {1} for reserved range.".format(IP,CIDR),err=True)
                        LinterError = True
        
        # Retrun if the reserved range is not valid
        if (LinterReservedRange):
            return LinterReservedRange
    
    if(WGMode):
        # Server
        serverInfo = networkDefiDict['WGNet']['Server']
        ### Port
        validPort = isValidPort(serverInfo['Port'])
        if (type(validPort) == dict and 'ErrorCode' in validPort):
            typer.echo("ERROR: {0}".format(validPort['ErrorMsg']),err=True)
            LinterError = True
        ### Routes
        RoutesList = serverInfo['Routes'].split(',')
        for route in RoutesList:
            validtest = isValidCIDR(route)
            if (type(validtest) == dict and 'ErrorCode' in validtest):
                typer.echo("ERROR : {0} is not the valid CIDR for server routes.".format(route),err=True)
                LinterError = True
        ### Public IP
        serverPublicIP = serverInfo['PublicIPAddress']
        validtest = isValidIP(serverPublicIP)
        if (type(validtest) == dict and 'ErrorCode' in validtest):
                typer.echo("ERROR : {0} is not the valid server public IP.".format(serverPublicIP),err=True)
                LinterError = True
        
        ### Private IP
        validtest = isValidIP(serverInfo['IPAddress'])
        if (type(validtest) == dict and 'ErrorCode' in validtest):
            typer.echo("ERROR : {0} is not the valid server IP.".format(serverInfo['IPAddress']),err=True)
            LinterError = True
        
    # Client
    clientIPs = getClientsIP(networkDefiDict,WGMode)
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
            typer.echo("ERROR: The client name of {0} has been used more than once.".format(name),err=True)
            LinterError = True
    ## hostname
    for hostname in clientHostname:
        if clientHostname.count(hostname) > 1:
            typer.echo("ERROR: The client hostname of {0} has been used more than once.".format(hostname),err=True)
            LinterError = True
    ## route
    if(WGMode):
        for client,route in clientRoute.items():
            RoutesList = route.split(',')
            for route in RoutesList:
                validtest = isValidCIDR(route)
                if (type(validtest) == dict and 'ErrorCode' in validtest):
                    typer.echo("ERROR : {0} is not the valid CIDR for client {1} routes.".format(route,client),err=True)
                    LinterError = True
        

    ## Check if the client has valid IP
    LinterUnvalidIPs = False
    unValidIPs = {}
    for client,IP in clientIPs.items():
        if isValidIP(IP) != True:
            unValidIPs[client] = IP
    if len(unValidIPs) > 0 :
        typer.echo("ERROR: These clients have not valid IP addresses",err=True)
        for client,IP in unValidIPs.items():
            typer.echo("{0} with IP of {1}".format(client,IP))
        LinterError = True
        LinterUnvalidIPs = True
    
    # should return if we have a unvalid IP
    if (LinterUnvalidIPs) :
        return LinterUnvalidIPs


    ## Check if client has IP not in the range of CIDR
    if(WGMode):
        notInNetworkIPs = {}
        for client,IP in clientIPs.items(): 
            if not isIPinCIDR(CIDR,IP):
                notInNetworkIPs[client] = IP
        if len(notInNetworkIPs) > 0:
            typer.echo("ERROR: These clients have IP addresses which are not in range of network {0}".format(CIDR),err=True)
            for client,IP in notInNetworkIPs.items():
                typer.echo("{0} with IP of {1}".format(client,IP))
            typer.echo("\n")
            LinterError = True

    ## Check if two clients have same IP Address
    duplicateIPs = findDuplicateIP(clientIPs)
    if len(duplicateIPs) > 0:
        typer.echo("ERROR: These clients have same IP addresses. Each client should have unique IP address.",err=True)
        for client,IP in duplicateIPs.items():
            typer.echo("{0} with IP of {1}".format(client,IP))
        typer.echo("\n")
        LinterError = True
    
    ## Check if the clients IP is range of rserved range
    if(WGMode):
        unRengedIPs = {}
        for client,IP in clientIPs.items(): 
            if not isIPinRange(ReservedRangeList,IP):
                unRengedIPs[client] = IP
        if len(unRengedIPs) > 0:
            typer.echo("ERROR: These clients have IP addresses which are not in range of reserved IPs {0}".format(networkDefiDict['WGNet']['ReservedRange']),err=True)
            for client,IP in unRengedIPs.items():
                typer.echo("{0} with IP of {1}".format(client,IP))
            typer.echo("\n")
            LinterError = True
    
    ## Check if the client has same IP as server
    if(WGMode):
        clientIPLikeServer= {}
        for client,IP in clientIPs.items():
            if IP == serverInfo['IPAddress']:
                clientIPLikeServer[client] = IP
        if len(clientIPLikeServer) > 0:
            typer.echo("ERROR: These clients have IP addresses eqaul to server IP address",err=True)
            for client,IP in clientIPLikeServer.items():
                typer.echo("{0} with IP of {1}".format(client,IP))
            typer.echo("\n")
            LinterError = True


    # NetworkResource
    if ('NetworkResources' in networkDefiDict):
        networkResources = networkDefiDict['NetworkResources']

        for resource in networkResources:
            if ('IPAddress' in resource):
                if ("/" in resource['IPAddress'] ):
                    validCIDR = isValidCIDR(resource['IPAddress'])
                    if (type(validCIDR) == dict and 'ErrorCode' in validCIDR):
                        typer.echo("ERROR: The Network {1} of network resource {0} is not valid .".format(resource['Name'],resource['IPAddress']),err=True)
                        LinterError = True
                else:
                    validIP = isValidIP(resource['IPAddress'])
                    if (type(validIP) == dict and 'ErrorCode' in validIP):
                        typer.echo("ERROR: The IP {1} of network resource {0} is not valid .".format(resource['Name'],resource['IPAddress']),err=True)
                        LinterError = True
    return LinterError


@app.command()
def initialize(
networkFile: Path = typer.Option(...,"--network-file",help="The network definition file"),
keyDirectory : Optional[Path] = typer.Option(None,"--keys-dir",help="The directory which contains clients public key for uncontrolled clients"),
graphName: str = typer.Option(None,"--graph-file-name",help="The generated GraphML file name. Default: Network Name"),
WGmode: bool = typer.Option(True,"--wg-mode/--no-wg-mode",help="WireGuard or Non-WireGuard mode. Default is WireGuard mode.")
):

    """
    WireGuard Mode: Get network definition file and intializie network and generate GraphML file

    Non-WireGuard Mode: Get network definition file and genrate GraphML file

    ------------

    Example:

    # Read network definition file and initialize network (WGMode)

    wgeasywall network initialize --network-file network1.yaml --keys-dir /home/wgeasywall/keysdir --graph-file-name network1
    
    ---
    
    # Read network definition file and generate GraphML file (No-WGMode)

    wgeasywall network initialize --network-file network2.yaml --graph-file-name network2 --no-wg-mode
    """
    
    if not networkFile.is_file():
        typer.echo("ERROR: Network Definition file can't be found!",err=True)
        raise typer.Exit(code=1)
    
    networkDefiDict = get_configuration(networkFile)

    if (type(dict) and 'ErrorCode' in networkDefiDict):

        typer.echo("ERORR: Can't read Network Definition file.  {0}".format(networkDefiDict['ErrorMsg']),err=True)
        raise typer.Exit(code=1)

    networkName = networkDefiDict['WGNet']['Name']
    if(WGmode):
        findNetworkQuery = {"_id": get_sha2(networkName)}
        queryNetwork = query_abstract(database_name='Networks',table_name='init',query=findNetworkQuery)
        if (type(queryNetwork) == dict and 'ErrorCode' in queryNetwork):
            typer.echo("ERROR: Can't connect to DB. Error: {0}".format(queryNetwork['ErrorMsg']),err=True)
            raise typer.Exit(code=1)
        
        networkInit = list(queryNetwork['Enteries'])
        if ( len(list(networkInit)) > 0 and networkInit[0]['initialized'] ):
            typer.echo("ERROR: The network {0} was initialized and can't be initialized again.".format(networkName),err=True)
            raise typer.Exit(code=1)

    # Lint
    LintError = linter(networkDefiDict,WGmode)
    if (LintError):
        typer.echo("Abort!")
        raise typer.Exit(code=1)
    
    # Check if the network subnet has overlap with others
    if(WGmode):
        CIDR = networkDefiDict['WGNet']['Subnet']
    
    clientsControlLevel = getClientBasedControlLevel(networkDefiDict,WGmode)

    networkDefiDictNoTouch = copy.deepcopy(networkDefiDict)

    # Keys
    if(WGmode):
        if (len(clientsControlLevel['Uncontrolled']) > 0 and keyDirectory == None):
            typer.echo("ERORR: There is more than one uncontrolled client in the network definition, keys directory should be specified!",err=True)
            raise typer.Exit(code=1)

        keysNotSet = False
        if (len(clientsControlLevel['Uncontrolled']) > 0):
            for client in clientsControlLevel['Uncontrolled']:
                clientKeyPath = "{0}/{1}.pb".format(keyDirectory,client['Name'])
                key = getFile(clientKeyPath)

                if (type(key) == dict):
                    typer.echo("ERROR: The key file '{0}.pub' for client: {0} can't be found in key directory!".format(client['Name']),err=True)
                    keysNotSet = True

        # If key is not found return
        if (keysNotSet):
            typer.echo('Initialization Fail!',err=True)
            raise typer.Exit(code=1)

    # Network Part
    if (graphName == None):
        graphName = networkName
    if(WGmode):
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
    if(WGmode):
        for client in clientsControlLevel['Uncontrolled']:
            clientKeyPath = "{0}/{1}.pb".format(keyDirectory,client['Name'])
            key = getFile(clientKeyPath)

            if (type(key) == dict):
                typer.echo("ERROR: The key file '{0}.pub' for client: {0} can't be found!".format(client),err=True)
                raise typer.Exit(code=1)
            client['PublicKey'] = key
            client['PrivateKey'] = ""

        for client in clientsControlLevel['Controlled']:
            clientKey = generateEDKeyPairs()
            client['PublicKey'] = clientKey[1]
            client['PrivateKey'] = clientKey[0]

    allClients =  clientsControlLevel['Controlled'] + clientsControlLevel['Uncontrolled']
    
    # Server
    if(WGmode):
        serverKey = generateEDKeyPairs()
        serverInfo['_id'] = get_sha2(serverInfo['Name'])
        serverInfo['PublicKey'] = serverKey[1]
        serverInfo['PrivateKey'] = serverKey[0]
        addResult = add_entry_one(database_name=networkName,table_name='server',data=serverInfo)
        if (type(addResult) == dict and 'ErrorCode' in addResult):
            typer.echo("ERORR: Can't connect to the database and initialize network",err=True)
            raise typer.Exit(code=1)
        
        # ADD ALL to DATABASE
        add_entry_multiple(database_name=networkName,table_name='freeIP',data=freeIPLIST)
        addResult = add_entry_one(database_name=networkName,table_name='subnet',data=CIDRData)
        if (type(addResult) == dict and 'ErrorCode' in addResult):
            typer.echo("ERORR: Can't connect to the database and initialize network",err=True)
            raise typer.Exit(code=1)
        
        typer.echo("IP-Assigner setup done.")
    
    defaultIP = '1.2.3.4'
    for client in allClients:
        client['_id'] = get_sha2(client['Name'])
        if(client['IPAddress'] == ""):
            if(WGmode):
                client['IPAddress'] = requestIP(networkName,client['Name'])
            else:
                client['IPAddress'] = defaultIP
        else:
            if(WGmode):
                client['IPAddress'] = requestIP(networkName,client['Name'],IP=client['IPAddress'])
    if(WGmode):
        add_entry_multiple(database_name=networkName,table_name='clients',data=allClients)

    allClients2addGraph = copy.deepcopy(allClients)
    
    for client in allClients2addGraph:
        client.pop('_id',None)
        client.pop('PublicKey',None)
        client.pop('PrivateKey',None)

    g = pyyed.Graph()
    addNodeCustomProperties(g)
    addEdgeCustomProperties(g)
    allGroupObject = generateGroupsObject(g,networkDefiDictNoTouch)
    generateGraph(allGroupObject,networkDefiDictNoTouch,g,allClients2addGraph,graphName,WGMode=WGmode)
    if(WGmode):
        add_entry_one(database_name='Networks',table_name='init',data={'_id':get_sha2(networkName),'network':networkName,'initialized':True, 'cidr':CIDR})
    exportGraphFile(g,graphName)

    # Upload Network File to DataBase
    if(WGmode):
        networkTempPath = create_temporary_copy(path=networkFile,networkName="{0}.yaml".format(networkName))
        netdefUniqueName = generate_slug(2)
        upload(db=networkName,fs='netdef',filePath=networkTempPath,uniqueName=netdefUniqueName)
        os.remove(networkTempPath)
        typer.echo("The provided Network definition is added to the database with the unique name of {0}. You can use this name to access the network definition.".format(netdefUniqueName))
    # TODO: Store GraphML to the database ?
    if(not WGmode):
        typer.echo("The Graphfile '{0}' is generated".format(graphName))

@app.command()
def update(
    networkFile: Path = typer.Option(...,"--network-file",help="The new network definition file"),
    oldNetworkFile: Optional[Path] = typer.Option(None,"--old-network-file",help="The old network definition file which will be used in case of WGMode is disabled"),
    WGmode: bool = typer.Option(True,"--wg-mode/--no-wg-mode",help="WG or normal mode. Default is WG mode."),
    keyDirectory : Optional[Path] = typer.Option(None,"--keys-dir",help="The directory which contains clients public key for uncontrolled clients"),
    graphFile: Path = typer.Option(...,"--graph-file",help="The GraphML file"),
    graphName: str = typer.Option(None,"--graph-file-name",help="The generated GraphML file name. Default: Network Name"),
    dryRun : Optional[bool] = typer.Option(False,"--dry-run",help="Only show the updates and not apply them."),
    graphDryRun: Optional[bool] = typer.Option(False,"--graph-dry-run",help="Only parse new network definition and existing graph file to generate new graph file. Not updating database based on the new network definition.")
):
    '''
    WGMode: Get new version of network definition and old version GraphML file to update network and generate new version of GraphML file

    No-WGMode: Get new and old version of network definition and old version GraphML file to generate new version of GraphML file

    ------------

    Example:

    # No-WGMode. Get new and old version of network definition file and GraphML file and generate new GraphML file 'NOWGUpdate'
    
    wgeasywall network update --network-file NOWG-NET-NEW.yaml --old-network-file  NOWG-NET-OLD.yaml --graph-file NOWG.graphml --graph-file-name NOWGUpdate --no-wg-mode

    ---

    # WGMode : Get new version of network definition file and GraphML file and generate new GraphML file

    wgeasywall network update --network-file net-graph-new.yaml --keys-dir /home/wgeasywall/keysdir --graph-file WGNet1-U.graphml


    '''
    if not networkFile.is_file():
        typer.echo("ERROR: Network Definition file can't be found!",err=True)
        raise typer.Exit(code=1)
    if (not WGmode and not oldNetworkFile.is_file()):
        typer.echo("ERROR: Old Network Definition file can't be found!",err=True)
        raise typer.Exit(code=1)
    if (not WGmode and oldNetworkFile==None):
        typer.echo("ERROR: If WG mode is disabled the old network definition should be specefied!",err=True)
        raise typer.Exit(code=1)
    if (not WGmode and graphDryRun):
        typer.echo("ERROR: Can't use Graph-dry-run when the WG mode is disabled!",err=True)
        raise typer.Exit(code=1)
    
    if not graphFile.is_file():
        typer.echo("ERROR: GraphML file can't be found!",err=True)
        raise typer.Exit(code=1)
    
    networkDefiDict = get_configuration(networkFile)

    if (type(dict) and 'ErrorCode' in networkDefiDict):

        typer.echo("ERORR: Can't read Network Definition file.  {0}".format(networkDefiDict['ErrorMsg']),err=True)
        raise typer.Exit(code=1)
    
    for client in networkDefiDict['WGNet']['Clients']:
        if('UnderControl' not in client):
            client['UnderControl'] = 'True'
    
    networkDefiDictNoTouch = copy.deepcopy(networkDefiDict)

    networkName = networkDefiDict['WGNet']['Name']
    networkNameNoTouch = networkName

    if (WGmode):
        isInitialized = isNetworkInitialized(networkName)
        if(type(isInitialized) == dict):
            if(isInitialized['ErrorCode'] == '900'):
                typer.echo(isInitialized['ErrorMsg'])
                typer.echo("Can't update the network {0} which is not initialized yet".format(networkName),err=True)
                raise typer.Exit(code=1)
            else:
                typer.echo("ERROR: Can't connect to the database. {0}".format(isInitialized),err=True)
                raise typer.Exit(code=1)

        # GET OLD Network Definition
        query = {'filename':'{0}.yaml'.format(networkName)}
        files = findAbstract(networkName,'netdef',query=query)
        oldNetworkDefiDict = yaml.safe_load(files[-1].read().decode())
    else:
        oldNetworkDefiDict = get_configuration(oldNetworkFile)
    
    for client in oldNetworkDefiDict['WGNet']['Clients']:
        if('UnderControl' not in client):
            client['UnderControl'] = 'True'

    # GraphDryRun
    if (graphDryRun):
        networkName = "{0}-dry".format(networkName)
        copy_db(srcName=networkNameNoTouch,targetName=networkName)
        add_entry_one(database_name='Networks',table_name='init',data={'_id':get_sha2(networkName),'network':networkName,'initialized':True, 'cidr':networkDefiDict['WGNet']['Subnet']})

    # Detect Difference between OLD and NEW in Server Settings 
    if(WGmode):
        serverInfo = networkDefiDict['WGNet']['Server']
        oldServerInfo = oldNetworkDefiDict['WGNet']['Server']

    ## Lint
    LintError = linter(networkDefiDict,WGmode)
    ### server name and hostname
    if(WGmode):
        if (serverInfo['Name'] != oldServerInfo['Name']):
            typer.echo("ERROR: The server's name can't be updated after initialization.",err=True)
            typer.echo("Update the server's name in the provided network defintion to {0} and re-run command.".format(oldServerInfo['Name']))
            LintError = True
        if (serverInfo['Hostname'] != oldServerInfo['Hostname']):
            typer.echo("ERROR: The server's hostname can't be updated after initialization.",err=True)
            typer.echo("Update the server's hostname in the provided network defintion to {0} and re-run command.".format(oldServerInfo['Name']))
            LintError = True
    ### ALL
    if (LintError):
        typer.echo("Update Abort.",err=True)
        raise typer.Exit(code=1)
    
    ## Server Detect Changes 
    if(WGmode):
        isServerChanged = False
        ### Port
        isChangeServerPort = (False,"","")
        if (serverInfo['Port'] != oldServerInfo['Port']):
            typer.echo("The server's port will be updated form {0} to {1} .".format(oldServerInfo['Port'],serverInfo['Port']))
            isChangeServerPort = (True,serverInfo['Port'],oldServerInfo['Port'])
            isServerChanged = True

    ### Routes
    if(WGmode):
        isChangeServerRoutes = (False,"","")
        if (serverInfo['Routes'] != oldServerInfo['Routes']):
            typer.echo("The server's routes will be updated form {0} to {1} .".format(oldServerInfo['Routes'],serverInfo['Routes']))
            isChangeServerRoutes = (True,serverInfo['Routes'],oldServerInfo['Routes'])
            isServerChanged = True
        
    ### Public IP
    if(WGmode):
        isChangeServerPublicIP = (False,"","")
        if (serverInfo['PublicIPAddress'] != oldServerInfo['PublicIPAddress']):
            typer.echo("The server's public IP address will be updated form {0} to {1} .".format(oldServerInfo['PublicIPAddress'],serverInfo['PublicIPAddress']))
            isChangeServerPublicIP = (True,serverInfo['PublicIPAddress'],oldServerInfo['PublicIPAddress'])
            isServerChanged = True 

    ### Private IP
    if(WGmode):
        isChangedServerIP = (False,"","")
        if (serverInfo['IPAddress'] != oldServerInfo['IPAddress']):
            isServerChanged = True
            typer.echo("The server's IP address will be updated form {0} to {1} .".format(oldServerInfo['IPAddress'],serverInfo['IPAddress']))
            if (serverInfo['IPAddress'] != oldServerInfo['IPAddress']):
            #### Check if the IP is available to assign
                IPQuery = {"IP":serverInfo['IPAddress']}
                IPQueryResult = query_abstract(database_name=networkName,table_name='leasedIP',query=IPQuery)
                if (type(IPQueryResult) == dict and 'ErrorCode' in IPQueryResult):
                    typer.echo("ERORR: Can't connect to the database. {0}".format(IPQueryResult['ErrorMsg']),err=True)
                    raise typer.Exit(code=1)
                IPQueryObject = list(IPQueryResult['Enteries'])
                if (len(IPQueryObject) > 0):
                    typer.echo("ERROR: The IP {0} is already leased and can't be assigned to Server.".format(serverInfo['IPAddress']),err=True)
                    LintError = True
                    raise typer.Exit(code=1)
            isChangedServerIP = (True,serverInfo['IPAddress'],oldServerInfo['IPAddress'])
        
    # Detect Difference between OLD and NEW in Network Settings
    if(WGmode):
        networkSettingsDiff = getNetDiff(networkDefiDict,oldNetworkDefiDict,networkNameNoTouch,'Net')['values_changed']

        isChangeSubnet = (False,"","")

        for item in networkSettingsDiff['Items']:
            
            if (item['AttributeChanged'] == 'ReservedRange'):
                typer.echo("ERROR: The reserved range is fixed and can't be changed after initialization.",err=True)
                typer.echo("Initialized value : {0} ".format(item['ObjectOldInfo']['ReservedRange']))
                typer.echo("New value : {0} ".format(item['ObjectNewInfo']['ReservedRange']))
                typer.echo("Please update the reserved range to initialized value and re-run command again")
                raise typer.Exit(code=1)

            if (item['AttributeChanged'] == 'Subnet'):
                newSubnet = item['ObjectNewInfo']['Subnet']
                oldSubnet = item['ObjectOldInfo']['Subnet']

                if not isLargerCIDR(newSubnet,oldSubnet):
                    typer.echo("ERROR: The new subnet {0} is not supernet of old subnet {1}.".format(newSubnet,oldSubnet),err=True)
                    typer.echo("The new subnet should be larger than old subnet")
                    typer.echo("Update Abort.",err=True)
                    raise typer.Exit(code=1)
                else:
                    typer.echo("The network subnet will be updated from {0} to {1}.".format(oldSubnet,newSubnet))
                    isChangeSubnet = (True,newSubnet,oldSubnet)

    ## Detect Client
    isClientChange = False # This attribute specify if we need to update clients 

    ### Should use a network definition that has not changed !!!!
    clientResult = getNetDiff(networkDefiDictNoTouch,oldNetworkDefiDict,networkNameNoTouch,'Clients')

    ### Detect Client Removed
    clientsRemoved = []
    for client in clientResult['iterable_item_removed']['Items']:
        
        clientsRemoved.append(client['ObjectInfo'])
        typer.echo("Client '{0}' will be removed from the network.".format(client['ObjectName']))
        isClientChange = True
    
    clientsAddedUnderControl = []
    clientsAddedNotUnderControl = []
    for client in clientResult['iterable_item_added']['Items']:
        if ('UnderControl' not in client['ObjectInfo']):
            clientsAddedUnderControl.append(client['ObjectInfo'])
        elif(client['ObjectInfo']['UnderControl'] == 'False'):
            clientsAddedNotUnderControl.append(client['ObjectInfo'])
        elif (client['ObjectInfo']['UnderControl'] == 'True'):
            clientsAddedUnderControl.append(client['ObjectInfo'])
        isClientChange = True
        typer.echo("Client '{0}' will be added to the network with these settings: \n{1}".format(client['ObjectName'],client['ObjectInfo']))
        if('UnderControl' in client['ObjectInfo'] and client['ObjectInfo']['UnderControl'] == 'False' and keyDirectory == None):
            if (WGmode):
                typer.echo("ERROR: Client is not under control which means the key direcotry should be specified.",err=True)
                raise typer.Exit(code=1)

    # Exit when the key file is not found
    if (WGmode):
        keysNotSet = False
        if (len(clientsAddedNotUnderControl) > 0):
            for client in clientsAddedNotUnderControl:
                clientKeyPath = "{0}/{1}.pb".format(keyDirectory,client['Name'])
                key = getFile(clientKeyPath)

                if (type(key) == dict):
                    typer.echo("ERROR: The key file '{0}.pub' for client: {0} can't be found!".format(client['Name']),err=True)
                    keysNotSet = True
        if (keysNotSet):
            typer.echo("Update Abort!",err=True)
            raise typer.Exit(code=1)
    
    ### Detect IP,Group,Routes Changed
    clientsIPChanged = []
    clientsGroupChanged = []
    isClientGroupChange = False # This variable check if the client group is changed
    clientsHostnameChanged = []
    clientsControlChanged = []
    clientsUnderControl = []
    clientNotUnderControl = []
    clientRouteChanged = []
    for client in clientResult['values_changed']['Items']:
        
        isClientChange = True
        if client['AttributeChanged'] == 'Routes':

            data = {
                'Name': client['ObjectName'],
                'Old': client['ObjectOldInfo']['Routes'],
                'New': client['ObjectNewInfo']['Routes']
            }
            typer.echo("Client '{0}' routes will be changed from {1} to {2}.".format(data['Name'],data['Old'],data['New']))
            clientRouteChanged.append(data)

        if client['AttributeChanged'] == 'UnderControl':
            data = {
                'Name': client['ObjectName'],
                'Old': client['ObjectOldInfo']['UnderControl'],
                'New': client['ObjectNewInfo']['UnderControl']
            }

            if (data['New'] == 'False'):
                clientNotUnderControl.append(data)
            if (data['New'] == 'True'):
                clientsUnderControl.append(data)

            typer.echo("Client '{0}' under-control attribute will be changed from {1} to {2}.".format(data['Name'],data['Old'],data['New']))
            clientsControlChanged.append(data)
        
        if client['AttributeChanged'] == 'Hostname':
            data = {
                'Name': client['ObjectName'],
                'Old': client['ObjectOldInfo']['Hostname'],
                'New': client['ObjectNewInfo']['Hostname']
            }
            typer.echo("Client '{0}' hostname will be changed from {1} to {2}".format(data['Name'],data['Old'],data['New']))
            clientsHostnameChanged.append(data)
        
        if client['AttributeChanged'] == 'Group':
            isClientGroupChange = True
            data = {
                'Name': client['ObjectName'],
                'Old': client['ObjectOldInfo']['Group'],
                'New': client['ObjectNewInfo']['Group']
            }
            typer.echo("Client '{0}' Group will be changed from {1} to {2}".format(data['Name'],data['Old'],data['New']))
            clientsGroupChanged.append(data)

        if client['AttributeChanged'] == 'IPAddress':
            data = {
                'Name': client['ObjectName'],
                'Old': client['ObjectOldInfo']['IPAddress'],
                'New': client['ObjectNewInfo']['IPAddress']
            }
            typer.echo("Client '{0}' IP address will be changed from {1} to {2}".format(data['Name'],data['Old'],data['New']))
            clientsIPChanged.append(data)
    if (len(clientNotUnderControl) > 0 and keyDirectory == None):
        typer.echo("ERROR: At least one client's control level will be changed to not under control which key direcotry should be specified.",err=True)
        raise typer.Exit(code=1)
    
    # # Exit when the key file is not found
    # keysNotSet = False
    # if (len(clientNotUnderControl) > 0):
    #     for client in clientNotUnderControl:
    #         clientKeyPath = "{0}/{1}.pb".format(keyDirectory,client['Name'])
    #         key = getFile(clientKeyPath)

    #         if (type(key) == dict):
    #             typer.echo("ERROR: The key file '{0}.pub' for client: {0} can't be found!".format(client['Name']))
    #             keysNotSet = True
    # if (keysNotSet):
    #     typer.echo("Update Abort!")
    #     raise typer.Exit(code=1)
    
    ### Detect Remove IP,Group,Routes
    clientsRemovedIP = []
    clientsRemovedGroup = []
    clientsRemovedRoutes = []
    for client in clientResult['dictionary_item_removed']['Items']:
        isClientChange = True
        if (client['AttributeRemoved'] == 'Routes'):

            data = {
                'Name': client['ObjectName'],
                'Old': client['ObjectOldInfo']['Routes']
            }
            typer.echo("Client '{0}' routes attributes will be removed and use network default route {1}.".format(data['Name'],serverInfo['Routes']))
            clientsRemovedRoutes.append(data)

        if (client['AttributeRemoved'] == 'Group'):
            isClientGroupChange = True
            data = {
                'Name': client['ObjectName'],
                'Old': client['ObjectOldInfo']['Group']
            }
            typer.echo("Client '{0}' group '{1}' will be removed.".format(data['Name'],data['Old']))
            clientsRemovedGroup.append(data)

        if (client['AttributeRemoved'] == 'IPAddress'):
            data = {
                'Name': client['ObjectName'],
                'Old': client['ObjectOldInfo']['IPAddress']
            }
            typer.echo("Client '{0}' will release its IP {1} and get dynamic IP.".format(data['Name'],data['Old']))
            clientsRemovedIP.append(data)
    
    ### Detect Add IP,Group,Routes
    clientsAddedIP = []
    clientsAddedGroup = []
    clientAddedRoutes = []
    for client in clientResult['dictionary_item_added']['Items']:
        isClientChange = True
        if (client['AttributeAdded'] == 'Routes'):

            data = {
                'Name': client['ObjectName'],
                'New': client['ObjectNewInfo']['Routes']
            } 
            typer.echo("Client '{0}' will get new routes {1} and doesn't use network defualt routes.".format(data['Name'],data['New']))
            clientAddedRoutes.append(client)

        if (client['AttributeAdded'] == 'Group'):
            isClientGroupChange = True
            data = {
                'Name': client['ObjectName'],
                'New': client['ObjectNewInfo']['Group']
            }
            typer.echo("Client {0} will be member of group {1} .".format(data['Name'],data['New']))
            clientsAddedGroup.append(data)

        if (client['AttributeAdded'] == 'IPAddress'):
            data = {
                'Name': client['ObjectName'],
                'New': client['ObjectNewInfo']['IPAddress']
            }
            typer.echo("Client {0} will get the IP address of {1} . ".format(data['Name'],data['New']))
            clientsAddedIP.append(data)
    
    # Check Enough IPs
    if (WGmode):
        subnetReport = getSubnetReport(networkName)
        
        ## Enough Static IPs will be detected from finding duplication in the Network Definition

        numFreeNonStaticIPs = subnetReport['NumFreeNonStaticIPs']

        numClientWithDynamicIPAdded = 0
        for client in (clientsAddedUnderControl + clientsAddedNotUnderControl):
            if ('IPAddress' not in client):
                numClientWithDynamicIPAdded += 1 
        
        numClientWithDynamicIPAdded += len(clientsRemovedIP)
        
        numDynamicIPAddedByClientRemoved = 0
        for client in clientsRemoved:
            if ('IPAddress' not in client):
                numDynamicIPAddedByClientRemoved += 1

        #numFreeStaticIPs = subnetReport['NumFreeStaticIPs']

        if (not isChangeSubnet[0] and numFreeNonStaticIPs+numDynamicIPAddedByClientRemoved-numClientWithDynamicIPAdded < 0):

            typer.echo("ERROR: There is no enough IPs to assign.",err=True)
            raise typer.Exit(code=1)

     
    # Dry-Run Feature
    if (dryRun):
        typer.echo("Dry-run....Update Abort!")
        raise typer.Exit(code=0)

    ## Update Server
    ### return back the IP and get new One 
    if(WGmode):
        if (isChangedServerIP[0]):
            freeIP = {}
            freeIP['_id'] = get_sha2(isChangedServerIP[2])
            freeIP['IP'] = str(isChangedServerIP[2])
            freeIP['static'] = 'True'

        
            addResult = add_entry_one(database_name=networkName,table_name='freeIP',data=freeIP)
            if (type(addResult) == dict and 'ErrorCode' in addResult):
                typer.echo("ERROR: Can't connect to the database. {0}".format(addResult),err=True)
                raise typer.Exit(code=1)
        
            requestResult = requestIP(networkName,serverInfo['Name'],IP=isChangedServerIP[1])
            if (type(requestResult) == dict and 'ErrorCode' in requestResult ):
                typer.echo ("ERROR: Can't request an IP for server. {0}".format(requestResult),err=True)
                raise typer.Exit(code=1)

            if (isServerChanged or isChangedServerIP[0]):
                serverQuery = { "_id": get_sha2(serverInfo['Name']) }
                serverNewValues = { "$set": { "IPAddress": serverInfo['IPAddress'], "PublicIPAddress": serverInfo['PublicIPAddress'], "Port": serverInfo['Port'], "Routes": serverInfo['Routes']  } }
                updateResult = update_one_abstract(database_name=networkName,table_name='server',query=serverQuery,newvalue=serverNewValues)
                if (type(UpdateResult) == dict and 'ErrorCode' in updateResult):
                    typer.echo("ERROR: Can't connet to the database. {0}".format(updateResult),err=True)
                    raise typer.Exit(code=1)
    
    ## Check if subnet is updated or not
    if(WGmode):
        serverInfo = networkDefiDict['WGNet']['Server']
    if (WGmode and isChangeSubnet[0]):

        ### Update subnet
        newCIDR = isChangeSubnet[1]
        oldCIDR = isChangeSubnet[2]

        additionalIPs = subtractCIDR(newCIDR,oldCIDR)
        
        newCIDRInfo = getCIDRInfo(newCIDR)

        #### Update init table
        networkQuery = {"_id":get_sha2(networkName)}
        newInitValue = { "$set": { "cidr": newCIDR } }
        resultUpadte = update_one_abstract(database_name='Networks',table_name='init',query=networkQuery,newvalue=newInitValue)
        if (type(resultUpadte) == dict and 'ErrorCode' in resultUpadte):
            typer.echo("ERORR: Can't connect to the database and initialize network",err=True)
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
            typer.echo("ERROR: Can't connect to the database. {0}".format(subnetTable),err=True)
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
    
    # Clients start changes

    ## Client IP Changed
    ### Release IPs
    if(WGmode):
        for client in clientsIPChanged:
            returnIP(networkName,clientName=client['Name'])

    if(WGmode):
        ### Get IPs
        for client in clientsIPChanged:

            newIP = requestIP(networkName,clientName=client['Name'],IP=client['New'])
            clientQuery = {"_id": get_sha2(client['Name'])}
            newValues = { "$set": { "IPAddress": newIP } }
            update_one_abstract(database_name=networkName,table_name='clients',query=clientQuery,newvalue=newValues)
    clientIPInjectToNetworkDef = {}
    if(WGmode):
        ## Client IP static removed
        
        for client in clientsRemovedIP:

            returnIP(networkName,clientName=client['Name'])

            newIP = requestIP(networkName,clientName=client['Name'])
            clientQuery = {"_id": get_sha2(client['Name'])}
            newValues = { "$set": { "IPAddress": newIP } }
            update_one_abstract(database_name=networkName,table_name='clients',query=clientQuery,newvalue=newValues)
            client['New'] = newIP
            clientIPInjectToNetworkDef[client['Name']] = newIP #These IP should be injected to the network definition
    if(WGmode):
        ## Client IP static Added
        for client in clientsAddedIP:
            
            returnIP(networkName,clientName=client['Name'])

            newIP = requestIP(networkName,clientName=client['Name'],IP=client['New'])
            clientQuery = {"_id": get_sha2(client['Name'])}
            newValues = { "$set": { "IPAddress": newIP } }
            update_one_abstract(database_name=networkName,table_name='clients',query=clientQuery,newvalue=newValues)

    ## Client Group,Routes,Hostname,UnderControl Change
    if(WGmode):
        for client in networkDefiDict['WGNet']['Clients']:
            
            if 'Group' not in client:
                group = 'Clients'
            else:
                group = client['Group']
            clientQuery = {"_id": get_sha2(client['Name'])}
            newValues = { "$set": { "Hostname": client['Hostname'], "UnderControl": client['UnderControl'], "Routes": client["Routes"], "Group": group } }
            update_one_abstract(database_name=networkName,table_name='clients',query=clientQuery,newvalue=newValues)

    if(WGmode):
        # Clients which are underControl
        for client in clientsUnderControl:
            
            keys = generateEDKeyPairs()
            clientQuery = {"_id": get_sha2(client['Name'])}
            newValues = { "$set": { "PublicKey": keys[1], "PrivateKey": keys[0]} }
            update_one_abstract(database_name=networkName,table_name='clients',query=clientQuery,newvalue=newValues)

    
    # Clients which are not underControl
    if(WGmode):
        for client in clientNotUnderControl:
            
            clientKeyPath = "{0}/{1}.pb".format(keyDirectory,client['Name'])
            key = getFile(clientKeyPath)

            if (type(key) == dict):
                typer.echo("ERROR: The key file '{0}.pub' for client: {0} can't be found!".format(client),err=True)
                raise typer.Exit(code=1)
            
            clientQuery = {"_id": get_sha2(client['Name'])}
            newValues = { "$set": { "PublicKey": key, "PrivateKey": "" } }
            update_one_abstract(database_name=networkName,table_name='clients',query=clientQuery,newvalue=newValues)

    # Clients Added
    ## NotUnderControl
    defaultIP = '1.2.3.4'
    for client in clientsAddedNotUnderControl:
        
        if(WGmode):
            clientKeyPath = "{0}/{1}.pb".format(keyDirectory,client['Name'])
            key = getFile(clientKeyPath)

            if (type(key) == dict):
                typer.echo("ERROR: The key file '{0}.pub' for client: {0} can't be found!".format(client),err=True)
                raise typer.Exit(code=1)
        
        if ('IPAddress' in client):
            if(WGmode):
                IP = requestIP(network=networkName,clientName=client['Name'],IP=client['IPAddress'])
                clientIPInjectToNetworkDef[client['Name']] = IP
            else:
                clientIPInjectToNetworkDef[client['Name']] = client['IPAddress']
        else:
            if(WGmode):
                IP = requestIP(network=networkName,clientName=client['Name'])
                clientIPInjectToNetworkDef[client['Name']] = IP
            else:
                clientIPInjectToNetworkDef[client['Name']] = defaultIP
        if(WGmode):
            clientRoute = ""
            if ('Routes' in client):
                clientRoute = client['Routes']
            else:
                clientRoute = serverInfo['Routes']

            clientGroup = ""
            if ('Group' in client):
                clientGroup = client['Group']

            clientData = {
                "_id": get_sha2(client['Name']),
                "Name": client['Name'],
                "Hostname": client['Hostname'],
                "UnderControl": client['UnderControl'],
                "Routes": clientRoute,
                "IPAddress": IP,
                "Group": clientGroup,
                "PublicKey": key,
                "PrivateKey": ""
            }
            
            add_entry_one(database_name=networkName,table_name='clients',data=clientData)

    ## UnderControl
    for client in clientsAddedUnderControl:
        
        if(WGmode):
            key = generateEDKeyPairs()

        if ('IPAddress' in client):
            if(WGmode):
                IP = requestIP(network=networkName,clientName=client['Name'],IP=client['IPAddress'])
                clientIPInjectToNetworkDef[client['Name']] = IP
            else:
                IP = defaultIP
                clientIPInjectToNetworkDef[client['Name']] = client['IPAddress']
        else:
            if(WGmode):
                IP = requestIP(network=networkName,clientName=client['Name'])
                clientIPInjectToNetworkDef[client['Name']] = IP
            else:
                IP = defaultIP
                clientIPInjectToNetworkDef[client['Name']] = defaultIP
        if(WGmode):
            clientRoute = ""
            if ('Routes' in client):
                clientRoute = client['Routes']
            else:
                clientRoute = serverInfo['Routes']

            clientGroup = "Clients"
            if ('Group' in client):
                clientGroup = client['Group']

            clientData = {
                "_id": get_sha2(client['Name']),
                "Name": client['Name'],
                "Hostname": client['Hostname'],
                "UnderControl": client['UnderControl'],
                "Routes": clientRoute,
                "IPAddress": IP,
                "Group": clientGroup,
                "PublicKey": key[1],
                "PrivateKey": key[0]
            }
            add_entry_one(database_name=networkName,table_name='clients',data=clientData)

    # Client Remove
    if(WGmode):
        for client in clientsRemoved:
            
            returnIP(network=networkName,clientName=client['Name'])

            clientQuery = {"_id": get_sha2(client['Name'])}

            delete_abstract_one(database_name=networkName,table_name='clients',query=clientQuery)
    

    # update network definition and inject client IP to network definition

    if (len(clientIPInjectToNetworkDef) > 0):
        for client in networkDefiDict['WGNet']['Clients']:

            if (client['Name'] in clientIPInjectToNetworkDef):
                client['IPAddress'] = clientIPInjectToNetworkDef[client['Name']]        

     
    # GraphML
    networkDefiForGraph = copy.deepcopy(networkDefiDictNoTouch)

    ## Update IPs
    nxGraph = nx.read_graphml(graphFile)
    if(WGmode):
        client2IP = mapClients2IP(network=networkName)
    for client in networkDefiForGraph['WGNet']['Clients']:
        if(WGmode):
            client['IPAddress'] = client2IP[client['Name']]
        else:
            if('IPAddress' not in client):
                clientsMapName2ID = parser.mapClientsIDName(nxGraph)
                if (client['Name'] in clientsMapName2ID):
                    clientID = clientsMapName2ID[client['Name']]
                    client['IPAddress'] = nxGraph.nodes[clientID]['IPAddress']
                else:
                    client['IPAddress'] = defaultIP

    if(graphName == None):
        graphName = networkName +'-Updated'
    
    edgeToDrawName,groupsColor,edgeToDrawID = getEdges2Draw(graphFile,networkDefiDictNoTouch,oldNetworkDefiDict)
    g = pyyed.Graph()
    addNodeCustomProperties(g)
    addEdgeCustomProperties(g)
    clientsControlLevel = getClientBasedControlLevel(networkDefiDictNoTouch,WGmode)
    allClients =  networkDefiForGraph['WGNet']['Clients']

    mapName2Hostname = {}
    for client in allClients:
        mapName2Hostname[client['Name']] = client['Hostname']
    if(WGmode):
        mapName2Hostname [serverInfo['Name']] = serverInfo['Hostname']
    else:
        mapName2Hostname['FW'] = 'FW.{0}'.format(networkName)
 
    allGroupObject = updateGroupsObject(g,networkDefiDictNoTouch,groupsColor)
    generateGraph(allGroupObject,networkDefiDictNoTouch,g,allClients,graphName,WGMode=WGmode)
    # Check if the Nodes are removed from network definition
    resourcesAndClients = getResourcesAndClients(networkDefiDictNoTouch)
    # edges2Draw,edges2DrawID = checkRemovedNodeInEdge(resourcesAndClients,edgeToDrawName,edgeToDrawID)
    edges2Draw = edgeToDrawName
    edges2DrawID = edgeToDrawID
    addEdges(g,edges2Draw,mapName2Hostname,edges2DrawID,nxGraph)
   
    exportGraphFile(g,graphName)
    # NOTE : EACH update should be executed with the graphfile and its corresponding graphfile , if not it cause inconssitency in the generated graphfile
    if (graphDryRun):
        delete_db(networkName)
        networkQuery = {"_id":get_sha2(networkName)}
        delete_abstract_one(database_name='Networks',table_name='init',query=networkQuery)
        raise typer.Exit(code=0)
    # Upload Network File to DataBase
    if(WGmode):
        networkTempPath = create_temporary_copy(path=networkFile,networkName="{0}.yaml".format(networkName))
        netdefUniqueName = generate_slug(2)
        upload(db=networkName,fs='netdef',filePath=networkTempPath,uniqueName=netdefUniqueName)
        os.remove(networkTempPath)
        typer.echo("The provided Network definition is added to the database with the unique name of {0}. You can use this name to access the network definition.".format(netdefUniqueName))

@app.command()
def clone(
    srcNetwork: str = typer.Option(...,"--src-network",help="The source network"),
    networkDefinitionName: str = typer.Option(...,"--network-definition-name",help="The unique name of network definition file. Use @latest to get the latest network definition"),
    dstNetwork: str = typer.Option(...,"--dst-network",help="The destination network"),
    keyDirectory : Optional[Path] = typer.Option(None,"--keys-dir",help="The directory which contains clients public key for uncontrolled clients")
):
    '''
    Get a source network name and network definition name and clone it as a new network

    ------------

    Example:

    # Clone network WGNet1 from latest network definition and create network WGNet2

    wgeasywall network clone --src-network WGNet1 --network-definition-name @latest --dst-network WGNet2
    '''
    # Check if the src network is already initialized 
    isInitialized = isNetworkInitialized(srcNetwork)
    if(type(isInitialized) == dict):
        if(isInitialized['ErrorCode'] == '900'):
            typer.echo(isInitialized['ErrorMsg'])
            raise typer.Exit(code=1)
        else:
            typer.echo("ERROR: Can't connect to the database. {0}".format(isInitialized),err=True)
            raise typer.Exit(code=1)
    
    # Check if the dst network is already initialized!
    isInitialized = isNetworkInitialized(dstNetwork)
    dstNetworkInit = False
    if(type(isInitialized) == dict):
        if(isInitialized['ErrorCode'] == '900'):
            dstNetworkInit = True
        else:
            typer.echo("ERROR: Can't connect to the database. {0}".format(isInitialized),err=True)
            raise typer.Exit(code=1)
    # TODO : Find Typo initialized -> initialized
    if not dstNetworkInit:
        typer.echo("ERROR: The destinition network {0} is already initialized and can't be used as destinition network.".format(dstNetwork),err=True)
        raise typer.Exit(code=1)

    if (networkDefinitionName == '@latest'):
        # GET OLD Network Definition
        query = {'filename':'{0}.yaml'.format(srcNetwork)}
        files = findAbstract(srcNetwork,'netdef',query=query)
        latestNetworkDefiDict = yaml.safe_load(files[-1].read().decode())

        ## Copy DB and init 
        copy_db(srcNetwork,dstNetwork)
        add_entry_one(database_name='Networks',table_name='init',data={'_id':get_sha2(dstNetwork),'network':dstNetwork,'initialized':True, 'cidr':latestNetworkDefiDict['WGNet']['Subnet']})


        ## update the network name to dst network
        latestNetworkDefiDict['WGNet']['Name'] = dstNetwork
        ## make the latest to file
        randomSuffix = ''.join(random.choices(string.ascii_uppercase + string.digits, k=N))
        latestFileName = "{0}-{1}.yaml".format(dstNetwork,randomSuffix)
        with open(latestFileName, 'w') as outfile:
            yaml.dump(latestNetworkDefiDict, outfile, default_flow_style=False)

        networkTempPath = create_temporary_copy(path=latestFileName,networkName="{0}.yaml".format(dstNetwork))
        netdefUniqueName = generate_slug(2)
        upload(db=dstNetwork,fs='netdef',filePath=networkTempPath,uniqueName=netdefUniqueName)
        os.remove(networkTempPath)
        os.remove(latestFileName)
        typer.echo("The {0} network is cloned to {1} network. The @latest network definition of network is cloned too with the unique name of {2}.".format(srcNetwork,dstNetwork,netdefUniqueName))

    else:
        query = {'filename':'{0}.yaml'.format(srcNetwork)}
        files = findAbstract(srcNetwork,'netdef',query=query)

        desiredFile = None
        for file in files:
            if(file.uniqueName == networkDefinitionName):
                desiredFile = file

        if (desiredFile == None):
            typer.echo("ERROR: The network definition with the unique name {0} is not found.".format(networkDefinitionName),err=True)
            raise typer.Exit(code=1)
        
        NetworkDefiDict = yaml.safe_load(desiredFile.read().decode())
        NetworkDefiDict['WGNet']['Name'] = dstNetwork
        randomSuffix = ''.join(random.choices(string.ascii_uppercase + string.digits, k=N))
        latestFileName = "{0}-{1}.yaml".format(dstNetwork,randomSuffix)
        with open(latestFileName, 'w') as outfile:
            yaml.dump(NetworkDefiDict, outfile, default_flow_style=False)
        
        typer.echo("Start clonning and initialization ....")
        initialize(networkFile=Path(latestFileName),
        keyDirectory=keyDirectory,graphName=dstNetwork)
        os.remove(latestFileName)
    
@app.command()
def remove(
    Network: str = typer.Option(...,"--network",help="The network which should be deleted")
):
    '''
    Get a network name and remove it from the database     

    ------------

    Example:

    # Remove network WGNet2

    wgeasywall network remove --network WGNet2
    '''
    # Check if the src network is already initialized 
    isInitialized = isNetworkInitialized(Network)
    if(type(isInitialized) == dict):
        if(isInitialized['ErrorCode'] == '900'):
            typer.echo(isInitialized['ErrorMsg'])
            raise typer.Exit(code=1)
        else:
            typer.echo("ERROR: Can't connect to the database. {0}".format(isInitialized),err=True)
            raise typer.Exit(code=1)
    
    typer.echo("Start removing network {0} ... ".format(Network))
    randomSuffix = ''.join(random.choices(string.ascii_uppercase + string.digits, k=N))
    directory = "{0}-{1}".format(Network,randomSuffix)
    currentDirectory = os.getcwd()
    dirPath = os.path.join(currentDirectory, directory)

    query = {'filename':'{0}.yaml'.format(Network)}
    files = findAbstract(Network,'netdef',query=query)

    os.mkdir(dirPath)
    for file in files:
        uploadDate = file.upload_date.strftime("%m-%d-%Y-%H-%M-%S")
        fileName = "{0}-{1}.yaml".format(file.uniqueName,uploadDate)
        fileFullPath = os.path.join(dirPath, fileName)

        NetworkDefiDict = yaml.safe_load(file.read().decode())
        
        with open(fileFullPath, 'w') as outfile:
            yaml.dump(NetworkDefiDict, outfile, default_flow_style=False)


    delete_db(Network)
    networkQuery = {"_id":get_sha2(Network)}
    result = delete_abstract_one(database_name='Networks',table_name='init',query=networkQuery)
    if(type(result) == dict and 'ErrorCode' in result ):
        typer.echo("ERROR: Can't connect to the database. {0}".format(result['ErrorMsg']),err=True)
        raise typer.Exit(code=1)

    typer.echo("The network {0} is removed and its network definition files are stored in the generated sub directory {1} .".format(Network,dirPath))

@app.command()
def generate_hosts_file(
    Network: str = typer.Option(...,"--network",help="The network which hosts file will be generated for")
):
    '''
    Get a network name and generate a hosts file which contains all mappings between nodes and their IP addresses

    ------------

    Example:

    # Generate hosts file for network WGNet1
    
    wgeasywall network generate-hosts-file --network WGNet1
    
    '''
    # Check if the src network is already initialized 
    isInitialized = isNetworkInitialized(Network)
    if(type(isInitialized) == dict):
        if(isInitialized['ErrorCode'] == '900'):
            typer.echo(isInitialized['ErrorMsg'])
            raise typer.Exit(code=1)
        else:
            typer.echo("ERROR: Can't connect to the database. {0}".format(isInitialized),err=True)
            raise typer.Exit(code=1)


    clientQuery = get_all_entries(database_name=Network,table_name='clients')
    if(type(clientQuery) == dict and 'ErrorCode' in clientQuery):
        typer.echo("ERROR: Can't connect to the database. {0}".format(clientQuery['ErrorMsg']),err=True)
        raise typer.Exit(code=1)
    
    clients = clientQuery['Enteries']

    serverQuery = get_all_entries(database_name=Network,table_name='server')
    if(type(serverQuery) == dict and 'ErrorCode' in serverQuery):
        typer.echo("ERROR: Can't connect to the database. {0}".format(serverQuery['ErrorMsg']),err=True)
        raise typer.Exit(code=1)
    server = serverQuery['Enteries'][0]


    randomSuffix = ''.join(random.choices(string.ascii_uppercase + string.digits, k=N))

    hostFileName = "{0}-{1}-{2}".format("Hosts",Network,randomSuffix)
    hosts = Hosts(path=hostFileName)

    hostEnteries = []

    serverEntry = HostsEntry(entry_type='ipv4', address=server['IPAddress'], names=[server['Name'], server['Hostname']])
    hostEnteries.append(serverEntry)

    for client in clients:
        entry = HostsEntry(entry_type='ipv4', address=client['IPAddress'], names=[client['Name'], client['Hostname']])
        hostEnteries.append(entry)
    
    hosts.add(hostEnteries)
    hosts.write()
    typer.echo("Hosts file '{0}' is generated in current working directory.".format(hostFileName))