import ipaddress
from netaddr import *
import netaddr
import networkx
from wgeasywall.utils.general.general import get_sha2
from wgeasywall.utils.mongo.table.get import *
from wgeasywall.utils.mongo.table.add import *
from wgeasywall.utils.mongo.table.delete import *
from wgeasywall.utils.mongo.table.update import *
from wgeasywall.utils.mongo.table.query import *
import datetime

# retund all clients IPs 
def mapClients2IP(network):

    IPdict = {}
    result = get_all_entries(database_name=network,table_name='leasedIP')
    if (type(result) == dict and 'ErrorCode' in result):
        return result
    clients =list(result['Enteries'])

    for client in clients:
        IPdict[client['Client']] = client['IP']
    return IPdict

def subtractCIDR(large,small):

    largeCidr = ipaddress.ip_network(large)
    smallCidr = ipaddress.ip_network(small)

    return sorted(list(set(largeCidr) - set(smallCidr)))


def findDuplicateIP(clientIPs):

    IPs = list(clientIPs.values())
    dedupIPs = {}
    for client,IP in clientIPs.items():
        if IPs.count(IP) > 1:
            dedupIPs[client] = IP
    return dedupIPs

def isValidPort(port):
    try:
        portNum = int(port)
        if not 49152 <= portNum <= 65535:
            return {'ErrorCode':'806','ErrorMsg':"The {0} is not Valid port number. Should be between 49152-65535 . ".format(port)}
    except ValueError:
        return {'ErrorCode':'806','ErrorMsg':"The {0} is not Valid port number.".format(port)}

def isValidCIDR(CIDR):
    try:
        ipaddress.ip_network(CIDR)
        return True
    except ValueError:
        return {'ErrorCode':'806','ErrorMsg':"The {0} is not Valid CIDR".format(CIDR)}

def isValidIP(IP):
    try:
        ipaddress.ip_address(IP)
        return True
    except ValueError:
        return {'ErrorCode':'806','ErrorMsg':"The {0} is not Valid IP Address".format(IP)}

def isIPinRange(range,IP):
    return netaddr.IPAddress(IP) in netaddr.IPRange(range[0],range[1])

def isIPinCIDR(CIDR,IP):

    return netaddr.IPAddress(IP) in netaddr.IPNetwork(CIDR)

def isStaticIPAvailable(network,IP):

    findIPQuery = {"IP": IP}
    queryResultObject= query_abstract(database_name=network,table_name='leasedIP',query=findIPQuery)
    if (type(queryResultObject) == dict and 'ErrorCode' in queryResultObject):
        return queryResultObject
    queryResult =list(queryResultObject['Enteries'])
    if(len(queryResult) > 0):
        return {"ErrorCode":"804","ErrorMsg":"{0} is reserved for client {1} and can't be assigned again".format(IP,queryResult[0]['Client'])}

    return True

def getSubnetReport(network):

    subnetReport = {}

    findNonStaticQuery = {"static":"False"}
    findStaticQuery = {"static":"True"}

    queryFreeNonStatic= query_abstract(database_name=network,table_name='freeIP',query=findNonStaticQuery)
    if (type(queryFreeNonStatic) == dict and 'ErrorCode' in queryFreeNonStatic):
        return queryFreeNonStatic
    
    freeNonStatic= list(queryFreeNonStatic['Enteries'])


    queryFreeStatic = query_abstract(database_name=network,table_name='freeIP',query=findStaticQuery)
    if (type(queryFreeStatic) == dict and 'ErrorCode' in queryFreeStatic):
        return queryFreeStatic

    freeStatic = list(queryFreeStatic['Enteries'])
    

    queryLeasedNonStatic = query_abstract(database_name=network,table_name='leasedIP',query=findNonStaticQuery)
    if (type(queryLeasedNonStatic) == dict and 'ErrorCode' in queryLeasedNonStatic):
        return queryLeasedNonStatic
    
    leasedNonStatic = list(queryLeasedNonStatic['Enteries'])

    queryLeasedStatic = query_abstract(database_name=network,table_name='leasedIP',query=findStaticQuery)
    if (type(queryLeasedStatic) == dict and 'ErrorCode' in queryLeasedStatic):
        return queryLeasedStatic
    
    leasedStatic = list(queryLeasedStatic['Enteries'])

    subnetReport = {
        'NumFreeNonStaticIPs': len(freeNonStatic),
        'FreeNonStaticIPs': freeNonStatic,
        'NumFreeStaticIPs': len(freeStatic),
        'FreeStaticIPs': freeStatic,
        'NumLeasedNonStaticIPs': len(leasedNonStatic),
        'LeasedNonStaticIPs': leasedNonStatic,
        'NumLeasedStaticIPs': len(leasedStatic),
        'LeasedStaticIPs': leasedStatic
    }

    return subnetReport

def getCIDRInfo(cidr):

    IPBlock = IPNetwork(cidr)
    IPInfo = {}
    IPInfo['CIDR'] = IPBlock.cidr
    IPInfo['FirstIP'] = IPBlock[1]
    IPInfo['LastIP'] = IPBlock[-2]
    IPInfo['Mask'] = IPBlock.netmask
    IPInfo['Size'] = IPBlock.size - 3  # Remove Network and Broadcast IP and Server
    return IPInfo

def isLargerCIDR(new_CIDR,old_CIDR):
    """
    Check the NEW CIDR is larger or supernet of OLD CIDR
    """
    
    # old_CIDR should be subnet of new_CIDR 
    newCidr = ipaddress.ip_network(new_CIDR)
    oldCidr = ipaddress.ip_network(old_CIDR)

    return oldCidr.subnet_of(newCidr)

def isOverlapCIDR(cidrA,cidrB):
    """
    Check if the CIDR A have overlap with CIDR B
    """
    return ipaddress.IPv4Network(cidrA).overlaps(ipaddress.IPv4Network(cidrB))

def returnIP(network,clientName):

    clientID = get_sha2(clientName)
    findClientQuery = {"_id": clientID}
    queryResultObject= query_abstract(database_name=network,table_name='leasedIP',query=findClientQuery)
    if (type(queryResultObject) == dict and 'ErrorCode' in queryResultObject):
        return queryResultObject
    queryResult =list(queryResultObject['Enteries'])

    if (len(queryResult) == 0):
        return {"ErrorCode":"802","ErrorMsg":"{0} has no leased IP address which can be released".format(clientName)}
    
    IP = queryResult[0]['IP']
    dataIP = {"_id": get_sha2(IP),"IP":IP,"static":queryResult[0]['static']}
    addResult = add_entry_one(database_name=network,table_name='freeIP',data=dataIP)
    deleteResult = delete_abstract_one(database_name=network,table_name='leasedIP',query=findClientQuery)
    
    return addResult

def requestIP(network,clientName,IP=None):

    # Check if the client has leased IPs
    clientID = get_sha2(clientName)
    findClientQuery = {"_id": clientID}
    queryResultObject= query_abstract(database_name=network,table_name='leasedIP',query=findClientQuery)
    if (type(queryResultObject) == dict and 'ErrorCode' in queryResultObject):
        return queryResultObject
    
    queryResult =list(queryResultObject['Enteries'])
    
    if(len(queryResult) > 0):
        return {"ErrorCode":"801","ErrorMsg":"{0} has an IP address of {1}. It's not possible to get another IP.".format(clientName,queryResult[0]['IP'])}

    if(IP==None):

        findIPQuery = {"static":"False"}
        queryResultObject= query_abstract(database_name=network,table_name='freeIP',query=findIPQuery)
        if (type(queryResultObject) == dict and 'ErrorCode' in queryResultObject):
            return queryResultObject
        queryResult =list(queryResultObject['Enteries'])
        if(len(queryResult) == 0):
            return {"ErrorCode":"805","ErrorMsg":"No IP available to assign"}
        
        ip2assign = queryResult[0]['IP']
        leaseDate = datetime.datetime.now().strftime("%d-%m-%Y-%H-%M-%S")
        leaseInfo = {"_id":get_sha2(clientName),"Client": clientName,"IP":str(ip2assign),"LeaseDate":leaseDate,"static":"False"}

        addResult = add_entry_one(database_name=network,table_name='leasedIP',data=leaseInfo)
        deleteResult = delete_abstract_one(database_name=network,table_name='freeIP',query=queryResult[0])
        if ('ErrorMsg' in addResult or 'ErrorMsg' in deleteResult):
            return addResult
        return ip2assign

    else:
        # Check if the IP is free
        findIPQuery = {"IP": IP}
        queryResultObject= query_abstract(database_name=network,table_name='leasedIP',query=findIPQuery)
        if (type(queryResultObject) == dict and 'ErrorCode' in queryResultObject):
            return queryResultObject
        queryResult =list(queryResultObject['Enteries'])
        if(len(queryResult) > 0):
            return {"ErrorCode":"804","ErrorMsg":"{0} is reserved for client {1} and can't be assigned to client {2}".format(IP,queryResult[0]['Client'],clientName)}

        # Find DesireIP and remove it from freeIP
        findIPQuery = {"IP": IP,"static":"True"}
        queryResultObject= query_abstract(database_name=network,table_name='freeIP',query=findIPQuery)
        if (type(queryResultObject) == dict and 'ErrorCode' in queryResultObject):
            return queryResultObject
        queryResult =list(queryResultObject['Enteries'])
        if(len(queryResult) == 0):
            return {"ErrorCode":"805","ErrorMsg":"{0} is not availble to assign".format(IP)}

        leaseDate = datetime.datetime.now().strftime("%d-%m-%Y-%H-%M-%S")
        leaseInfo = {"_id":get_sha2(clientName),"Client": clientName,"IP":str(IP),"LeaseDate":leaseDate,"static":"True"}

        addResult = add_entry_one(database_name=network,table_name='leasedIP',data=leaseInfo)
        deleteResult = delete_abstract_one(database_name=network,table_name='freeIP',query=findIPQuery)
        if ('ErrorMsg' in addResult or 'ErrorMsg' in deleteResult):
            return addResult
        return IP

def releaseIP(network,clientName):

    clientID = get_sha2(clientName)
    findClientQuery = {"_id": clientID}
    queryResultObject= query_abstract(database_name=network,table_name='leasedIP',query=findClientQuery)
    if (type(queryResultObject) == dict and 'ErrorCode' in queryResultObject):
        return queryResultObject
    queryResult =list(queryResultObject['Enteries'])

    if (len(queryResult) == 0):
        return {"ErrorCode":"802","ErrorMsg":"{0} has no leased IP address which can be released".format(clientName)}

    IP = queryResult[0]['IP']
    dataIP = {"_id": get_sha2(IP),"IP":IP}
    addResult = add_entry_one(database_name=network,table_name='freeIP',data=dataIP)
    deleteResult = delete_abstract_one(database_name=network,table_name='leasedIP',query=findClientQuery)
    return addResult


def getIP(network,clientName):

    # Check if the client has leased IPs
    clientID = get_sha2(clientName)
    findClientQuery = {"_id": clientID}
    queryResultObject= query_abstract(database_name=network,table_name='leasedIP',query=findClientQuery)
    if (type(queryResultObject) == dict and 'ErrorCode' in queryResultObject):
        return queryResultObject
    
    queryResult =list(queryResultObject['Enteries'])
    
    if(len(queryResult) > 0):
        return {"ErrorCode":"801","ErrorMsg":"{0} has an IP address of {1}. It's not possible to get another IP.".format(clientName,queryResult[0]['IP'])}

    # Check Free IP table
    freeIPsObject = get_all_entries(network,'freeIP')
    if (type(freeIPsObject) == dict and 'ErrorCode' in freeIPsObject):
        return freeIPsObject
    freeIPs = list(freeIPsObject['Enteries'])

    if (len(freeIPs) == 0):

        subnetObject = get_all_entries(network,'subnet')
        if (type(subnetObject) == dict and 'ErrorCode' in subnetObject):
            return subnetObject
        subnet = list(subnetObject['Enteries'])[0]

        serverIP = IPAddress(subnet['serverIP'])
        nextIP = IPAddress(subnet['nextIP'])
        if (serverIP == nextIP):
            nextIP = nextIP + 1
        cidr = IPNetwork(subnet['cidr'])
        
        if( (cidr.broadcast) == (nextIP)):
            return {"ErrorCode":"800","ErrorMsg":"There is no available IP address for new client. PLEASE update network subnet to support more IPs."}

        assignedIP = nextIP

        newNextIP = nextIP + 1
        newSize = subnet['size'] - 1

        leaseDate = datetime.datetime.now().strftime("%d-%m-%Y-%H-%M-%S")
        leaseInfo = {"_id":get_sha2(clientName),"Client": clientName,"IP":str(assignedIP),"LeaseDate":leaseDate}
        results = add_entry_one(database_name=network,table_name='leasedIP',data=leaseInfo)
        
        if (type(results) == dict and 'ErrorCode' in results):
            return results

        updateQuery = {"_id" : subnet['_id']}
        updateValue = { "$set": {"nextIP": str(newNextIP),"size": newSize} }
        results = update_one_abstract(database_name=network,table_name='subnet',query=updateQuery,newvalue=updateValue)
        return assignedIP
    else:

        freeIP = freeIPs[0]
        assignedIP = freeIP['IP']
        leaseDate = datetime.datetime.now().strftime("%d-%m-%Y-%H-%M-%S")
        leaseInfo = {"_id":get_sha2(clientName),"Client": clientName,"IP":str(assignedIP),"LeaseDate":leaseDate}
        resultsAdd = add_entry_one(database_name=network,table_name='leasedIP',data=leaseInfo)
        
        if (type(resultsAdd) == dict and 'ErrorCode' in resultsAdd):
            return resultsAdd
        deleteResult = delete_abstract_one(database_name=network,table_name='freeIP',query=freeIP)
        if (type(deleteResult) == dict and 'ErrorCode' in deleteResult):
            return deleteResult
        
        return assignedIP

    

    

    

    




