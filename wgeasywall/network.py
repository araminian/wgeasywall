from pathlib import Path
from sys import path
from typing import Dict

import netaddr
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

app = typer.Typer()

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

    clientIPs = getClientsIP(networkDefiDict)

    # Check if the client has valid IP
    unValidIPs = {}
    for client,IP in clientIPs.items():
        if isValidIP(IP) != True:
            unValidIPs[client] = IP
    if len(unValidIPs) > 0 :
        typer.echo("ERROR: These clients have not valid IP addresses")
        for client,IP in unValidIPs.items():
            typer.echo("{0} with IP of {1}".format(client,IP))
        raise typer.Exit(code=1)

    # Check if client has IP not in the range of CIDR
    notInNetworkIPs = {}
    for client,IP in clientIPs.items(): 
        if not isIPinCIDR(CIDR,IP):
            notInNetworkIPs[client] = IP
    if len(notInNetworkIPs) > 0:
        typer.echo("ERROR: These clients have IP addresses which are not in range of network {0}".format(CIDR))
        for client,IP in notInNetworkIPs.items():
            typer.echo("{0} with IP of {1}".format(client,IP))
        typer.echo("\n")

    # Check if two clients have same IP Address
    duplicateIPs = findDuplicateIP(clientIPs)
    if len(duplicateIPs) > 0:
        typer.echo("ERROR: These clients have same IP addresses. Each client should have unique IP address.")
        for client,IP in duplicateIPs.items():
            typer.echo("{0} with IP of {1}".format(client,IP))
        typer.echo("\n")
    
    # Check if the clients IP is range of rserved range
    unRengedIPs = {}
    for client,IP in clientIPs.items(): 
        if not isIPinRange(ReservedRange,IP):
            unRengedIPs[client] = IP
    if len(unRengedIPs) > 0:
        typer.echo("ERROR: These clients have IP addresses which are not in range of reserved IPs {0}".format(networkDefiDict['WGNet']['ReservedRange']))
        for client,IP in unRengedIPs.items():
            typer.echo("{0} with IP of {1}".format(client,IP))
        typer.echo("\n")
    
    if (len(notInNetworkIPs) > 0 or len(duplicateIPs) > 0 or len(unRengedIPs) > 0):
        raise typer.Exit(code=1)
    
    

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