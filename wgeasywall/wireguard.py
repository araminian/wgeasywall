from re import sub, subn
import typer 
from wgeasywall.utils.wireguard.query import *
import wgeasywall.utils.wireguard.models as wg_models
from wgeasywall.utils.wireguard.generator import *
from netaddr import IPAddress
from typing import Optional
from wgeasywall.utils.general.filedir import getFile
from wgeasywall.utils.nacl.keyGenerate import generateEDKeyPairs
from wgeasywall.utils.mongo.core.collection import get_collection
from wgeasywall.utils.mongo.table.add import *

app = typer.Typer()

def serverGenerate(clients,server,subnet,outputDir,networkName):
    # Generate Server Configuration
    serverAddress = server['IPAddress']
    serverMask =IPAddress(subnet['mask']).netmask_bits()
    ServerInterface =  wg_models.InterfaceModel (
    PrivateKey = wg_models.KeyModel(Key=server['PrivateKey']),
    ListenPort = int(server['Port']),
    CommentKey = "Interface" ,
    CommentValue = networkName,
    Address = "{0}/{1}".format(serverAddress,serverMask)
            )

    clientAsPeer = []

    for client in clients:
        clientModel = wg_models.PeerModel(
            PublicKey = wg_models.KeyModel(Key=client['PublicKey']),
            AllowedIPs = ["{0}/32".format(client['IPAddress'])],
            CommentKey = "Client" , 
            CommentValue = client['Name']
                )
        clientAsPeer.append(generate_peer(clientModel))
            
    configComponents = wg_models.ConfigComponentsModel(
    Interface = generate_interface(ServerInterface),
    Peers = clientAsPeer,
    ConfigPath = '{0}/wg-server.conf'.format(outputDir)
        )
    generate_wg_conf_file(configComponents)



def clientGenerate(clients,server,subnet,outputDir):
    serverMask =IPAddress(subnet['mask']).netmask_bits()
    clientUnControll = []


    for client in clients:
        if (client['PrivateKey'] == ''):
            client['PrivateKey'] = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk="
            clientUnControll.append(client['Name'])
                
        # TODO do we need listenport for client ? 
        clientInterface = wg_models.InterfaceModel (
        PrivateKey = wg_models.KeyModel(Key=client['PrivateKey']),
        ListenPort = 51820,
        CommentKey = "Interface" ,
        CommentValue = client['Name'],
        Address = "{0}/{1}".format(client['IPAddress'],serverMask)
            )
        clientRoute = client['Routes'].split(",")

        serverAsPeer = wg_models.PeerModel(
        PublicKey = wg_models.KeyModel(Key=server['PublicKey']),
        AllowedIPs = clientRoute,
        Endpoint = wg_models.EndpointModel (
        Address = server['PublicIPAddress'],
        Port = int(server['Port'])
                ),
                CommentKey = "Peer" , 
                CommentValue = "Server"
            )
        serverPeer = []
        serverPeer.append(generate_peer(serverAsPeer))
        configComponentsClient = wg_models.ConfigComponentsModel(
        Interface = generate_interface(clientInterface),
            Peers = serverPeer,
            ConfigPath = '{1}/wg-{0}.conf'.format(client['Name'],outputDir)
                )
        generate_wg_conf_file(configComponentsClient)
    return clientUnControll


@app.command()
def generate(
    networkName: str = typer.Option(...,"--network",help="The network name which is initialized"),
    all: bool = typer.Option(False,"--all",help="Re-generate all configuration again. True or False"),
    clients2Config: str = typer.Option(None,"--clients",help="A list of clients which configurations will be generated for them"),
    outputDir: Path = typer.Option(...,"--output-dir",help="The directory which the generated configuration will be saved"),
    isServer: bool = typer.Option(False,"--server",help="Re-generate server configuration")
):
    """
    Generate or regenerate wireguard configuration

    ------------

    Example:

    # Generate wireguard configuration files for all nodes in 'WGNet1' and store it '/home/wgeasywall/wgconf' directroy

    wgeasywall wireguard generate --network WGNet1 --all --output-dir /home/wgeasywall/wgconf

    ---

    # Generates 'Client1 and Client2' and 'server' wireguard configuration file

    wgeasywall wireguard generate --network WGNet1 --clients Client1,Client2 --server --output-dir /home/wgeasywall/wgconf

    ---

    # Only generate 'server' wireguard configuration file 

    wgeasywall wireguard generate --network WGNet1 --server --output-dir /home/wgeasywall/wgconf

    """
    isInitialized = isNetworkInitialized(networkName)
    if(type(isInitialized) == dict):
        if(isInitialized['ErrorCode'] == '900'):
            typer.echo(isInitialized['ErrorMsg'])
            raise typer.Exit(code=1)
        else:
            typer.echo("ERROR: Can't connect to the database. {0}".format(isInitialized),err=True)
            raise typer.Exit(code=1)
    # all take priority   
    if (all):
        allAsk = typer.confirm("Do you want re-generate all server and clients configurations?")
        if (not allAsk):
            typer.echo("Abort")
            typer.Exit(code=0)
        else:
            # If All selected
            clients = getClients(networkName)
            server = getServer(networkName)
            subnet = getSubnet(networkName)

            if (type(clients) == dict and 'ErrorCode' in clients):
                typer.echo("ERROR: Can't connect to the database to get clients. {0}".format(clients),err=True)
                raise typer.Exit(code=1)
            
            if (type(server) == dict and 'ErrorCode' in server):
                typer.echo("ERROR: Can't connect to the database to get server. {0}".format(server),err=True)
                raise typer.Exit(code=1)
            
            if (type(subnet) == dict and 'ErrorCode' in subnet):
                typer.echo("ERROR: Can't connect to the database to subnet. {0}".format(server),err=True)
                raise typer.Exit(code=1)

            # Generate Server Configuration
            
            serverGenerate(clients,server,subnet,outputDir,networkName)

            # Generate Clients
            clientUnControll = clientGenerate(clients,server,subnet,outputDir)

            if (len(clientUnControll) > 0):
                typer.echo("WARNING : These clients are not under our control. You should edit private key part of configuration and add correct private key : ")
                for unclient in clientUnControll:
                    typer.echo(unclient) 
            typer.Exit(code=0)

    if (isServer):
        # If server is selected
        clients = getClients(networkName)
        server = getServer(networkName)
        subnet = getSubnet(networkName)

        if (type(clients) == dict and 'ErrorCode' in clients):
            typer.echo("ERROR: Can't connect to the database to get clients. {0}".format(clients),err=True)
            raise typer.Exit(code=1)
            
        if (type(server) == dict and 'ErrorCode' in server):
            typer.echo("ERROR: Can't connect to the database to get server. {0}".format(server),err=True)
            raise typer.Exit(code=1)
            
        if (type(subnet) == dict and 'ErrorCode' in subnet):
            typer.echo("ERROR: Can't connect to the database to subnet. {0}".format(server),err=True)
            raise typer.Exit(code=1)

        # Generate Server Configuration
            
        serverGenerate(clients,server,subnet,outputDir,networkName)

    if(clients2Config != None):

        client2Generate = clients2Config.split(",")
        clients = []
        for client in client2Generate:
            queryResult = query_abstract(database_name=networkName,table_name='clients',query={'_id':get_sha2(client)})
            if ('ErrorCode' in queryResult):
                typer.echo("ERROR: Can't connect to the database. {0}".format(queryResult),err=True)
                raise typer.Exit(code=1)
                
            clientQueryObject = list(queryResult['Enteries'])
            if len(clientQueryObject) == 0:
                typer.echo("ERROR: Client {0} doesn't exist in the network".format(client),err=True)
                raise typer.Exit(code=1)
            clients.append(clientQueryObject[0])
        
        server = getServer(networkName)
        subnet = getSubnet(networkName)

        
        if (type(server) == dict and 'ErrorCode' in server):
            typer.echo("ERROR: Can't connect to the database to get server. {0}".format(server),err=True)
            raise typer.Exit(code=1)
            
        if (type(subnet) == dict and 'ErrorCode' in subnet):
            typer.echo("ERROR: Can't connect to the database to subnet. {0}".format(server),err=True)
            raise typer.Exit(code=1)

        clientUnControll = clientGenerate(clients,server,subnet,outputDir)
        if (len(clientUnControll) > 0):
                typer.echo("WARNING : These clients are not under our control. You should edit private key part of configuration and add correct private key : ")
                for unclient in clientUnControll:
                    typer.echo(unclient) 

@app.command()
def key_generate(
networkName: str = typer.Option(...,"--network",help="The network name which is initialized"),
all: bool = typer.Option(False,"--all",help="Update all keys. True or False"),
clients2Config: str = typer.Option(None,"--clients-list",help="A list of clients which their keys should be updated"),
outputDir: Optional[Path] = typer.Option(None,"--output-dir",help="The directory which the generated configuration will be saved"),
isServer: bool = typer.Option(False,"--server",help="Update server key"),
isClients: bool = typer.Option(False,"--clients",help="Update all clients keys"),
keyDirectory : Optional[Path] = typer.Option(None,"--keys-dir",help="The directory which contains clients public key for uncontrolled clients"),
):
    """
    Update server and clients keys and regenerate wireguard configuration files

    ------------

    Example:

    # Update clients keys and not regenerate wireguard configuration file

    wgeasywall wireguard key-generate --network WGNet1 --clients --keys-dir /home/wgeasywall/keysdir

    ---

    # Update clients keys and regenerate wireguard configuration files
    wgeasywall wireguard key-generate --network WGNet1 --clients --keys-dir /home/wgeasywall/keysdir --output-dir /home/wgeasywall/wgconf

    ---

    # Update only server keys and regenerate all wireguard configuration file

    wgeasywall wireguard key-generate --network WGNet1 --server --output-dir /home/wgeasywall/wgconf

    """

    isInitialized = isNetworkInitialized(networkName)
    if(type(isInitialized) == dict):
        if(isInitialized['ErrorCode'] == '900'):
            typer.echo(isInitialized['ErrorMsg'])
            raise typer.Exit(code=1)
        else:
            typer.echo("ERROR: Can't connect to the database. {0}".format(isInitialized),err=True)
            raise typer.Exit(code=1)
    # all take priority   
    if (all):
        allAsk = typer.confirm("Do you want update all server and clients keys?")
        if (not allAsk):
            typer.echo("Abort")
            typer.Exit(code=0)
        else:
            # If All selected
            clients = getClients(networkName)
            server = getServer(networkName)
            subnet = getSubnet(networkName)

            if (type(clients) == dict and 'ErrorCode' in clients):
                typer.echo("ERROR: Can't connect to the database to get clients. {0}".format(clients),err=True)
                raise typer.Exit(code=1)
            
            if (type(server) == dict and 'ErrorCode' in server):
                typer.echo("ERROR: Can't connect to the database to get server. {0}".format(server),err=True)
                raise typer.Exit(code=1)
            
            if (type(subnet) == dict and 'ErrorCode' in subnet):
                typer.echo("ERROR: Can't connect to the database to subnet. {0}".format(server),err=True)
                raise typer.Exit(code=1)

            clientControlled, clientNotControlled = getClientsControlLevel(clients)

            if (len(clientNotControlled) > 0 and keyDirectory == None):
                typer.echo("ERORR: There is more than one uncontrolled client , keys directory should be specified!",err=True)
                raise typer.Exit(code=1)

            # Clients Keys
            for client in clientNotControlled:
                clientKeyPath = "{0}/{1}.pb".format(keyDirectory,client['Name'])
                key = getFile(clientKeyPath)

                if (type(key) == dict):
                    typer.echo("ERROR: The key file '{0}.pub' for client: {0} can't be found!".format(client),err=True)
                    raise typer.Exit(code=1)
                client['PublicKey'] = key
                client['PrivateKey'] = ""
            
            for client in clientControlled:
                clientKey = generateEDKeyPairs()
                client['PublicKey'] = clientKey[1]
                client['PrivateKey'] = clientKey[0]

            allCients = clientNotControlled + clientControlled

            # Server Key
            serverKey = generateEDKeyPairs()
            server['PublicKey'] = serverKey[1]
            server['PrivateKey'] = serverKey[0]

            clientTable = get_collection(db_name=networkName,collection_name='clients')
            serverTable = get_collection(db_name=networkName,collection_name='server')

            if (type(clientTable) == dict and 'ErrorCode' in clientTable):
                typer.echo("ERROR: Can't connect to the database. {0}".format(clientTable),err=True)
                raise typer.Exit(code=1)
            if (type(serverTable) == dict and 'ErrorCode' in serverTable):
                typer.echo("ERROR: Can't connect to the database. {0}".format(serverTable),err=True)
                raise typer.Exit(code=1)
            
            clientTable.drop()
            serverTable.drop()

            add_entry_one(database_name=networkName,table_name='server',data=server)
            add_entry_multiple(database_name=networkName,table_name='clients',data=allCients)

            if (outputDir == None):
                typer.echo("Skip re-generating configurations. It can be done later.")
                typer.Exit(code=0)
            else:
                typer.echo("Re-generating configuration ... \n")
                # Generate Server Configuration
                serverGenerate(clients,server,subnet,outputDir,networkName)

                # Generate Clients
                clientUnControll = clientGenerate(clients,server,subnet,outputDir)

                if (len(clientUnControll) > 0):
                    typer.echo("WARNING : These clients are not under our control. You should edit private key part of configuration and add correct private key : ")
                    for unclient in clientUnControll:
                        typer.echo(unclient) 
                typer.Exit(code=0)

    if (isServer):
        # If server is selected
        clients = getClients(networkName)
        server = getServer(networkName)
        subnet = getSubnet(networkName)

        if (type(clients) == dict and 'ErrorCode' in clients):
            typer.echo("ERROR: Can't connect to the database to get clients. {0}".format(clients),err=True)
            raise typer.Exit(code=1)
            
        if (type(server) == dict and 'ErrorCode' in server):
            typer.echo("ERROR: Can't connect to the database to get server. {0}".format(server),err=True)
            raise typer.Exit(code=1)
            
        if (type(subnet) == dict and 'ErrorCode' in subnet):
            typer.echo("ERROR: Can't connect to the database to subnet. {0}".format(server),err=True)
            raise typer.Exit(code=1)

        # Server Key
        serverKey = generateEDKeyPairs()
        server['PublicKey'] = serverKey[1]
        server['PrivateKey'] = serverKey[0]
        
        serverTable = get_collection(db_name=networkName,collection_name='server')
        if (type(serverTable) == dict and 'ErrorCode' in serverTable):
                typer.echo("ERROR: Can't connect to the database. {0}".format(serverTable),err=True)
                raise typer.Exit(code=1)
            
        serverTable.drop()
        add_entry_one(database_name=networkName,table_name='server',data=server)
    
    # ALL Clients
    if (isClients):
        clientsName = []
        clients = getClients(networkName)
        if (type(clients) == dict and 'ErrorCode' in clients):
            typer.echo("ERROR: Can't connect to the database to get clients. {0}".format(clients),err=True)
            raise typer.Exit(code=1)
        for client in clients:
            clientsName.append(client['Name'])
        clients2Config = ",".join(clientsName)

    if(clients2Config != None):

        client2Generate = clients2Config.split(",")
        clients = []
        clientsName = []

        for client in client2Generate:
            queryResult = query_abstract(database_name=networkName,table_name='clients',query={'_id':get_sha2(client)})
            if ('ErrorCode' in queryResult):
                typer.echo("ERROR: Can't connect to the database. {0}".format(queryResult))
                raise typer.Exit(code=1)
                
            clientQueryObject = list(queryResult['Enteries'])
            if len(clientQueryObject) == 0:
                typer.echo("ERROR: Client {0} doesn't exist in the network".format(client),err=True)
                raise typer.Exit(code=1)
            clients.append(clientQueryObject[0])
            clientsName.append(client)

        server = getServer(networkName)
        subnet = getSubnet(networkName)
        allClients = getClients(networkName)

        
        if (type(server) == dict and 'ErrorCode' in server):
            typer.echo("ERROR: Can't connect to the database to get server. {0}".format(server),err=True)
            raise typer.Exit(code=1)
        if (type(subnet) == dict and 'ErrorCode' in subnet):
            typer.echo("ERROR: Can't connect to the database to subnet. {0}".format(server),err=True)
            raise typer.Exit(code=1)
        if (type(clients) == dict and 'ErrorCode' in clients):
            typer.echo("ERROR: Can't connect to the database to get clients. {0}".format(clients),err=True)
            raise typer.Exit(code=1)
        
        clientControlled, clientNotControlled = getClientsControlLevel(clients)

        clientControlledName = []
        clientNotControlledName = []

        for client in clientControlled:
            clientControlledName.append(client['Name'])
        for client in clientNotControlled:
            clientNotControlledName.append(client['Name'])
        
        if (len(clientNotControlled) > 0 and keyDirectory == None):
                typer.echo("ERORR: There is more than one uncontrolled client, keys directory should be specified!",err=True)
                raise typer.Exit(code=1)

        for client in allClients:
            if(client['Name'] in clientControlledName):
                clientKey = generateEDKeyPairs()
                client['PublicKey'] = clientKey[1]
                client['PrivateKey'] = clientKey[0]
            elif(client['Name'] in clientNotControlledName):
                clientKeyPath = "{0}/{1}.pb".format(keyDirectory,client['Name'])
                key = getFile(clientKeyPath)
                # TODO: Check before if the key file is exist or not ?!
                if (type(key) == dict):
                    typer.echo("ERROR: The key file '{0}.pub' for client: {0} can't be found!".format(client),err=True)
                    raise typer.Exit(code=1)
                client['PublicKey'] = key
                client['PrivateKey'] = ""
        
        clientTable = get_collection(db_name=networkName,collection_name='clients')

        if (type(clientTable) == dict and 'ErrorCode' in clientTable):
            typer.echo("ERROR: Can't connect to the database. {0}".format(clientTable),err=True)
            raise typer.Exit(code=1)
            
        clientTable.drop()

        add_entry_multiple(database_name=networkName,table_name='clients',data=allClients)

    # Check when clients or server configuration should be generated
    if (outputDir == None):
        typer.echo("Skip re-generating configurations. It can be done later.")
        typer.Exit(code=0)
    else:
        if (isServer):
            
            server = getServer(networkName)
            subnet = getSubnet(networkName)
            allClients = getClients(networkName)

            typer.echo("Re-generating configuration ... \n")
            # Generate Server Configuration
            serverGenerate(allClients,server,subnet,outputDir,networkName)

                # Generate Clients
            clientUnControll = clientGenerate(allClients,server,subnet,outputDir)

            if (len(clientUnControll) > 0):
                typer.echo("WARNING : These clients are not under our control. You should edit private key part of configuration and add correct private key : ")
                for unclient in clientUnControll:
                    typer.echo(unclient) 

        elif( not isServer and clients2Config != None):
            client2Generate = clients2Config.split(",")
            clients = []
            
            allClients = getClients(networkName)
            server = getServer(networkName)
            subnet = getSubnet(networkName)

            for client in client2Generate:
                queryResult = query_abstract(database_name=networkName,table_name='clients',query={'_id':get_sha2(client)})
                if ('ErrorCode' in queryResult):
                    typer.echo("ERROR: Can't connect to the database. {0}".format(queryResult),err=True)
                    raise typer.Exit(code=1)
                    
                clientQueryObject = list(queryResult['Enteries'])
                if len(clientQueryObject) == 0:
                    typer.echo("ERROR: Client {0} doesn't exist in the network".format(client),err=True)
                    raise typer.Exit(code=1)
                clients.append(clientQueryObject[0])
            
            typer.echo("Re-generating configuration ... \n")
            # Generate Server Configuration , Server needs all clients
            serverGenerate(allClients,server,subnet,outputDir,networkName)

            # Generate Clients
            clientUnControll = clientGenerate(clients,server,subnet,outputDir)

            if (len(clientUnControll) > 0):
                typer.echo("WARNING : These clients are not under our control. You should edit private key part of configuration and add correct private key : ")
                for unclient in clientUnControll:
                    typer.echo(unclient)




        











