from re import finditer
from pymongo import results
import yaml
from wgeasywall.utils.mongo.table import get
import typer
from wgeasywall.vars import *
import wgeasywall.config as config
import wgeasywall.network as network
from wgeasywall.utils.general.configParser import get_configuration
from wgeasywall.utils.mongo.core.db import get_db
import gridfs
from wgeasywall.utils.mongo.gridfsmongo import *
from wgeasywall.utils.nacl.IPUtils import *
from pathlib import Path
from wgeasywall.utils.parse.networkdefinition import *
from netaddr import IPAddress
import wgeasywall.view as view
import wgeasywall.wireguard as wireguard
import wgeasywall.ruleAsCode as ruleAsCode
import wgeasywall.iptable as iptable

app = typer.Typer()
app.add_typer(config.app,name="config",help="Commands related to configuration generator")
app.add_typer(network.app,name="network",help="Commands related to WireGuard networks and graph")
app.add_typer(view.app,name="view",help="Commands related to reporting")
app.add_typer(wireguard.app,name="wireguard",help="Commands related to wireguard and its configurations")
app.add_typer(ruleAsCode.app,name='RaaC',help="Commands related to the Rule as a Code and its configurations")
app.add_typer(iptable.app,name='IPTables',help="Commands related to generating IPTables rules")

@app.callback()
def main(ctx: typer.Context):

    if (ctx.invoked_subcommand == "config"):
        return
    
    mongoConfigPath = get_mongo_configuration_location()

    # MONGO
    mongoConfiguration = get_configuration(mongoConfigPath)

    if ('ErrorCode' in mongoConfiguration):
        if(mongoConfiguration['ErrorCode'] == "404"):
            typer.echo("ERROR: The mongo.yaml file can't be found please use CLI to generate it",err=True)
            typer.Abort()
            raise typer.Exit(code=1)
        else:
            typer.echo("ERROR: mongo.yaml",err=True)
            typer.echo(mongoConfiguration['ErrorMsg'],err=True)
            typer.Abort()
            raise typer.Exit(code=1)



app()
# ------------------------- Pickle and Json ------------------------
# import json
# import pickle

# class MyClass:
#   x = 5

# p1 = MyClass()

# pick_data = pickle.dumps(p1)

# data = pickle.loads(pick_data)
# print(data.x)

# ------------------------- Temp File ------------------------
# import tempfile

# temp = tempfile.NamedTemporaryFile(mode='w+t')
# try:
#     print(temp.name)
#     temp.write('This is a test')
#     temp.seek(0)
#     print(temp.read())
# finally:
#     temp.close()


# ------------------------- Parse Network File ------------------------

# netdef = get_configuration('net-sample.yaml')

# nets = getServer(netdef)

# print(nets)

# clientIPs = getClientsIP(netdef)
# print(findDuplicateIP(clientIPs))

# ------------------------- FileDir ------------------------

# listMatch = getFilesInDir(Path('/home/armin/Thesis/WireGuard-Config-Generator/wgeasywall/wgeasywall'),'*.yaml')
# content = readFile(listMatch[0])
# print(content)
# ------------------------- Network ------------------------

# net = ipaddress.IPv4Network('192.168.0.0/24')
# for ip in net:
#     print(ip)

# result = getCIDRInfo('192.168.0.0/24')

# for ip in result['CIDR']:
#     print(ip)
# print(result)

# isLarge = isLargerCIDR('192.168.0.0/25',"192.168.0.0/24")
# print(isLarge)

# isOverLAP = isOverlapCIDR('192.168.0.0/24','192.167.0.0/22')
# print(isOverLAP)

# IP = requestIP('WGNet1','client32',IP='192.168.0.50')
# print(IP)

# report = getSubnetReport('WGNet1')
# print(report)


# result = isStaticIPAvailable('WGNet1','192.168.0.51')
# print(result)

# result = isIPinCIDR('192.168.0.0/24','192.168.1.1')
# print(result)

# result = isIPinRange(['192.168.0.1','192.168.0.50'],'192.168.0.200')
# print(result)

# IP = getIP('WGNet1','client4')
# print(IP)

#result=releaseIP('WGNet1','client1')
#print(result)

# ------------------------- GridFS------------------------
# entry = get_configuration('net-sample.yaml')
# db = get_db('test')
# fs = gridfs.GridFS(db,collection='network')
# with open('net-sample.yaml','rb') as f:
#     contents = f.read()
# fs.put(contents,filename='net-sample.yaml')


# yamltest = fs.get_last_version(filename='net-sample.yaml')
# res = yaml.load(yamltest.read(),Loader=yaml.FullLoader)
# print(res['WGNets'])
# findres = fs.find({"filename":"net-sample.yaml"})
# for f in findres:
#     print(f.upload_date)

#deleteOldest('test','network','net-sample.yaml',2,3)
# res = getAll('test','network','net-sample.yaml')
# for f in res:
#     print(f._id)
#upload('test','network','net-sample.yaml')
# latest = getLatest('test','network','net-sample.yaml')
# pp = pprint.PrettyPrinter(indent=2)
# print(latest.decode()) # view yaml file
#uploadWithUniqueName('test','network','net-sample.yaml',uniqueName='Hell')
# test = findAbstract('test','network',{'filename':'net-sample.yaml','uniqueName':'Hell'})
# for t in test:
#     print(t)
# ------------------------- GridFS------------------------
