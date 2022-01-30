from re import sub
from sys import argv

import yaml
from wgeasywall.utils.mongo import table
import typer
from wgeasywall.utils.mongo.table.get import *
from wgeasywall.utils.mongo.table.query import *
from tabulate import *
from wgeasywall.utils.general.general import *
from wgeasywall.utils.nacl.IPUtils import getSubnetReport
from wgeasywall.utils.mongo.gridfsmongo import *
from wgeasywall.utils.ruleAsCode.function import extractFunctionDefinition
from wgeasywall.utils.ruleAsCode.action import extractActionDefinition

app = typer.Typer()
raac = typer.Typer()

app.add_typer(raac,name='RaaC',help="Reporting Rule as a Code")

@app.command()
def networks():

    """
    Get all Initialized network 
    """

    network = get_all_entries(database_name='Networks',table_name='init')

    if (type(network) == dict and 'ErrorCode' in network):
        typer.echo("ERROR: Can't connect to the database.  {0}".format(network),err=True)
        raise typer.Exit(code=1)

    networkInit = list(network['Enteries'])

    if (len(networkInit) == 0 ):
        typer.echo("No initialized network have been found.")

    net = []
    for n in networkInit:
        data = []
        data.append(n['network'])
        net.append(data)
    typer.echo(tabulate(net,headers=['Network Name'],tablefmt="pretty"))

@app.command()
def subnet_report(
    networkName: str = typer.Option(...,"--network",help="The network name which is initialized")
):
    
    """
    Get full reports of network's subnet like FreeIPs,AssignedIPS,....
    """
    queryNetwork = {"_id": get_sha2(networkName)}
    network = query_abstract(database_name='Networks',table_name='init',query=queryNetwork)

    if (type(network) == dict and 'ErrorCode' in network):
        typer.echo("ERROR: Can't connect to the database.  {0}".format(network),err=True)
        raise typer.Exit(code=1)

    networkInit = list(network['Enteries'])

    if (len(networkInit) == 0 ):
        typer.echo("The network {0} is not initialized.".format(networkName))
    

    subnet = get_all_entries(database_name=networkName,table_name='subnet')
    if (type(subnet) == dict and 'ErrorCode' in subnet):
        typer.echo("ERROR: Can't connect to the database.  {0}".format(subnet),err=True)
        raise typer.Exit(code=1)

    subnetObject = list(subnet['Enteries'])[0]

    data=[networkName,subnetObject['cidr'],subnetObject['mask'],subnetObject['firstIP'],subnetObject['lastIP'],subnetObject['serverIP']]
    tableData = []
    tableData.append(data)

    typer.echo("Subnet Report")
    typer.echo(tabulate(tableData,headers=['Network Name','CIDR','Subnet Mask','First IP','Last IP','Server IP'],tablefmt="pretty"))

    subnetReport = getSubnetReport(networkName)



    data = [subnetReport['NumFreeNonStaticIPs'],subnetReport['NumFreeStaticIPs'],subnetReport['NumLeasedNonStaticIPs'],subnetReport['NumLeasedStaticIPs']]
    tableData = []
    tableData.append(data)

    typer.echo("Subnet number of leased and free IPs")
    typer.echo(tabulate(tableData,headers=['Number of free non-static IPs','Number of free static IPs','Number of leased non-static IPs','Number of leased static IPs'],tablefmt="pretty"))


    LeasedNonStaticIPs = subnetReport['LeasedNonStaticIPs']
    
    tableData = []

    for lease in LeasedNonStaticIPs:
        data = [lease['Client'],lease['IP'],lease['LeaseDate']]
        tableData.append(data)
    typer.echo("\nLeased non-static IPs")
    typer.echo(tabulate(tableData,headers=['Client Name','IP','Lease Data'],tablefmt="pretty"))

    tableData = []
    LeasedStaticIPs = subnetReport['LeasedStaticIPs']
    for lease in LeasedStaticIPs:
        data = [lease['Client'],lease['IP'],lease['LeaseDate']]
        tableData.append(data)
    typer.echo("\nLeased static IPs")
    typer.echo(tabulate(tableData,headers=['Client Name','IP','Lease Data'],tablefmt="pretty"))

@app.command()
def network_definition(
    networkName: str = typer.Option(...,"--network",help="The network name which is initialized"),
    networkDefinitionName: str = typer.Option(None,"--network-definition-name",help="The unique name of network definition file. Use @latest to get the latest network definition")
):

    """
    Get network definition. Use only --network to list all network definitions. Use --network-definition-name to get
    the network definition.
    """

    queryNetwork = {"_id": get_sha2(networkName)}
    network = query_abstract(database_name='Networks',table_name='init',query=queryNetwork)

    if (type(network) == dict and 'ErrorCode' in network):
        typer.echo("ERROR: Can't connect to the database.  {0}".format(network),err=True)
        raise typer.Exit(code=1)

    networkInit = list(network['Enteries'])

    if (len(networkInit) == 0 ):
        typer.echo("The network {0} is not initialized.".format(networkName))
        raise typer.Exit(code=0)
    query = {'filename':'{0}.yaml'.format(networkName)}
    files = findAbstract(networkName,'netdef',query=query)
    

    if (networkDefinitionName == None):
        tableData = []
        for file in files:
            data=[file.filename,file.uniqueName,file.upload_date]
            tableData.append(data)
        typer.echo(tabulate(tableData,headers=['File Name','Unique Name','Upload Date'],tablefmt="pretty"))
    elif (networkDefinitionName=='@latest'):
        typer.echo("Get latest upload network definition....")
        typer.echo("-"*20)
        typer.echo(files[-1].read().decode())
    else:
        tableData = []
        desiredFile = None 
        for file in files:
            if(file.uniqueName == networkDefinitionName):
                desiredFile = file
                data=[file.filename,file.uniqueName,file.upload_date]
                tableData.append(data)
                break
        if(len(tableData)>0):
            typer.echo(tabulate(tableData,headers=['File Name','Unique Name','Upload Date'],tablefmt="pretty"))
            typer.echo("-"*20)
            
            typer.echo(desiredFile.read().decode())
        else:
            typer.echo("The network definition with the unique name of {0} can't be found".format(networkDefinitionName))

@app.command()
def clients(
    networkName: str = typer.Option(...,"--network",help="The network name which is initialized"),
    verbose: int = typer.Option(0,"--verbose","-v",count=True)
):

    """
    Get Clients in the initialized network

    -v : Get Name, Hostname ,IPAddress ,Group

    -vv : Get -v items plus Routes, Under Control

    -vvv : Get --v items plus Public Key
    """
    
    queryNetwork = {"_id": get_sha2(networkName)}
    network = query_abstract(database_name='Networks',table_name='init',query=queryNetwork)

    if (type(network) == dict and 'ErrorCode' in network):
        typer.echo("ERROR: Can't connect to the database.  {0}".format(network),err=True)
        raise typer.Exit(code=1)

    networkInit = list(network['Enteries'])

    if (len(networkInit) == 0 ):
        typer.echo("The network {0} is not initialized.".format(networkName))
        raise typer.Exit(code=0)
    
    clients = get_all_entries(database_name=networkName,table_name='clients')
    if (type(clients) == dict and 'ErrorCode' in clients):
        typer.echo("ERROR: Can't connect to the database.  {0}".format(clients),err=True)
        raise typer.Exit(code=1)

    clientList = list(clients['Enteries'])

    if(verbose == 0):
        simpleView = []
        for client in clientList:
        
            if 'Group' not in client:
                client['Group'] = '-'

            simpleData = [client['Name'],client['Hostname'],client['IPAddress'],client['Group']]
            simpleView.append(simpleData)
        typer.echo(tabulate(simpleView,headers=['Name','Hostname','IPAddress','Group'],tablefmt="pretty"))
    elif(verbose == 1):
        normalView = []
        for client in clientList:
        
            if 'Group' not in client:
                client['Group'] = '-'

            Data = [client['Name'],client['Hostname'],client['IPAddress'],client['Group'],client['Routes'],client['UnderControl']]
            normalView.append(Data)

        typer.echo(tabulate(normalView,headers=['Name','Hostname','IPAddress','Group','Routes','Under Control'],tablefmt="pretty"))
    elif(verbose > 1):
        advanceView = []
        for client in clientList:
        
            if 'Group' not in client:
                client['Group'] = '-'

            Data = [client['Name'],client['Hostname'],client['IPAddress'],client['Group'],client['Routes'],client['UnderControl'],client['PublicKey']]
            advanceView.append(Data)
        typer.echo(tabulate(advanceView,headers=['Name','Hostname','IPAddress','Group','Routes','Under Control','Public Key'],tablefmt="pretty"))

# TODO : change method based on query in the wireguard module

@app.command()
def server(
    networkName: str = typer.Option(...,"--network",help="The network name which is initialized"),
    verbose: int = typer.Option(0,"--verbose","-v",count=True)
):
    """
    Get Server in the initialized network

    -v : Get Name, Hostname ,IPAddress ,PublicIPAddress

    -vv : Get -v items plus Port, Routes

    -vvv : Get --v items plus Public Key
    """

    queryNetwork = {"_id": get_sha2(networkName)}
    network = query_abstract(database_name='Networks',table_name='init',query=queryNetwork)

    if (type(network) == dict and 'ErrorCode' in network):
        typer.echo("ERROR: Can't connect to the database.  {0}".format(network),err=True)
        raise typer.Exit(code=1)

    networkInit = list(network['Enteries'])

    if (len(networkInit) == 0 ):
        typer.echo("The network {0} is not initialized.".format(networkName))
        raise typer.Exit(code=0)
    
    server = get_all_entries(database_name=networkName,table_name='server')
    if (type(server) == dict and 'ErrorCode' in server):
        typer.echo("ERROR: Can't connect to the database.  {0}".format(server),err=True)
        raise typer.Exit(code=1)

    serverObject = list(server['Enteries'])[0]

    if(verbose == 0):
        simpleView = []

        simpleData = [serverObject['Name'],serverObject['Hostname'],serverObject['IPAddress'],serverObject['PublicIPAddress']]
        simpleView.append(simpleData)
        typer.echo(tabulate(simpleView,headers=['Name','Hostname','IPAddress','PublicIPAddress'],tablefmt="pretty"))
    elif(verbose == 1):
        normalView = []
        

        Data = [serverObject['Name'],serverObject['Hostname'],serverObject['IPAddress'],serverObject['PublicIPAddress'],serverObject['Port'],serverObject['Routes']]
        normalView.append(Data)

        typer.echo(tabulate(normalView,headers=['Name','Hostname','IPAddress','PublicIPAddress','Port','Routes'],tablefmt="pretty"))
    elif(verbose > 1):
        advanceView = []
        
        Data = [serverObject['Name'],serverObject['Hostname'],serverObject['IPAddress'],serverObject['PublicIPAddress'],serverObject['Port'],serverObject['Routes'],serverObject['PublicKey']]
        advanceView.append(Data)
        typer.echo(tabulate(advanceView,headers=['Name','Hostname','IPAddress','PublicIPAddress','Port','Routes','Public Key'],tablefmt="pretty"))


@raac.command()
def action(
    action: str = typer.Option(None,"--action",help="The action name"),
    version: str = typer.Option(None,"--version",help="The version of action. Use @latest to get the latest"),
    all: bool = typer.Option(False,"--all",help="Use to get all actions in the database")
):  
    '''
    Get actions in the database or get action manifest file

    ------------

    Example:

    # Get all actions

    wgeasywall view RaaC action --all

    ---

    # Get lists of all versions of 'LOG' action in the database

    wgeasywall RaaC action --action LOG

    ---

    # Get 'latest' action manifest file of 'LOG' action 

    wgeasywall RaaC action --action LOG --version @latest
    '''
    if(all):
        result = getAllInFS('RaaC','action')
        if (type(result) == dict and 'ErrorCode' in result):
            typer.echo("ERROR: {0}".format(result['ErrorMsg']),err=True)
            raise typer.Exit(code=1)
        tableData = []
        for act in result:
            query = {'filename':'{0}'.format(act)}
            files = findAbstract('RaaC','action',query=query)
            for file in files:
                Data = [file.filename.split(".")[0],file.uniqueName,file.upload_date]
                tableData.append(Data)
        typer.echo(tabulate(tableData,headers=['Action Name','Version','Upload Date'],tablefmt="pretty"))
        raise typer.Exit(code=0)

    if (action != None and version == None):

        query = {'filename':'{0}.yaml'.format(action)}
        files = findAbstract('RaaC','action',query=query)

        if(len(files) == 0):
            typer.echo("ERROR: The Action '{0}' doesn't exist on the database.".format(action),err=True)
            raise typer.Exit(code=1)

        tableData = []
        for file in files:
                Data = [file.filename.split(".")[0],file.uniqueName,file.upload_date]
                tableData.append(Data)
        typer.echo(tabulate(tableData,headers=['Action Name','Version','Upload Date'],tablefmt="pretty"))
        raise typer.Exit(code=0)

    if (action != None and version != None):

        actionDefinition = extractActionDefinition(action=action,version=version)

        if (type(actionDefinition) == dict and 'ErrorCode' in actionDefinition):
            typer.echo('ERROR: {0}'.format(actionDefinition['ErrorMsg']),err=True)
            raise typer.Exit(code=1)
        
        actionMainBody = actionDefinition['Action']['Body']['Main']
        actionArguments = actionDefinition['Action']['Body']['Arguments']
        argumentsList = []
        for argName,argValue in actionArguments.items():
            argumentsList.append(argValue['Definition'])
        typer.echo("Action Syntax:\n")
        typer.echo('{0} {1}'.format(actionMainBody,' '.join(argumentsList)))

        typer.echo('-'*10)
        typer.echo("Action Manifest:\n")
        typer.echo(yaml.dump(actionDefinition))

@raac.command()
def function(
    function: str = typer.Option(None,"--function",help="The function name"),
    version: str = typer.Option(None,"--version",help="The version of function. Use @latest to get the latest"),
    all: bool = typer.Option(False,"--all",help="Use to get all functions in the database")
):
    '''
    Get functions in the database or get action manifest file

    ------------

    Example:

    # Get all functions

    wgeasywall view RaaC function --all

    ---

    # Get lists of all versions of 'conntrack' action in the database

    wgeasywall RaaC function --action conntrack

    ---

    # Get 'latest' function manifest file of 'conntrack' action 

    wgeasywall RaaC function --function conntrack --version @latest
    '''
    
    if(all):
        result = getAllInFS('RaaC','function')
        if (type(result) == dict and 'ErrorCode' in result):
            typer.echo("ERROR: {0}".format(result['ErrorMsg']),err=True)
            raise typer.Exit(code=1)
        tableData = []
        for func in result:
            query = {'filename':'{0}'.format(func)}
            files = findAbstract('RaaC','function',query=query)
            for file in files:
                Data = [file.filename.split(".")[0],file.uniqueName,file.upload_date]
                tableData.append(Data)
        typer.echo(tabulate(tableData,headers=['Function Name','Version','Upload Date'],tablefmt="pretty"))
        raise typer.Exit(code=0)

    if (function != None and version == None):

        query = {'filename':'{0}.yaml'.format(function)}
        files = findAbstract('RaaC','function',query=query)

        if(len(files) == 0):
            typer.echo("ERROR: The Function '{0}' doesn't exist on the database.".format(function),err=True)
            raise typer.Exit(code=1)

        tableData = []
        for file in files:
                Data = [file.filename.split(".")[0],file.uniqueName,file.upload_date]
                tableData.append(Data)
        typer.echo(tabulate(tableData,headers=['Function Name','Version','Upload Date'],tablefmt="pretty"))
        raise typer.Exit(code=0)

    if (function != None and version != None):

        functionDefinition = extractFunctionDefinition(function=function,version=version)

        if (type(functionDefinition) == dict and 'ErrorCode' in functionDefinition):
            typer.echo('ERROR: {0}'.format(functionDefinition['ErrorMsg']),err=True)
            raise typer.Exit(code=1)

        typer.echo("Function Syntax:\n")
        funcMainBody = functionDefinition['Func']['Body']['Main']
        functArguments = functionDefinition['Func']['Body']['Arguments']
        argumentsList = []
        for argName,argValue in functArguments.items():
            argumentsList.append(argValue['Definition'])
        typer.echo('{0} {1}'.format(funcMainBody,' '.join(argumentsList)))
        
        typer.echo('-'*10)
        typer.echo("Function Manifest:\n")

        typer.echo(yaml.dump(functionDefinition))

        
        
            





        



