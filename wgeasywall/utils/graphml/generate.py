import pyyed
import random
import yaml

def readNetDefination(filePath) -> dict:
    with open(filePath, 'r') as stream:
      try:
          data= yaml.safe_load(stream)
      except yaml.YAMLError as exc:
          print(exc)
    return data

def getRandomColor():
    r = lambda: random.randint(105,255)
    color = ('#%02X%02X%02X' % (r(),r(),r()))
    return color

def findGroupsInNetworkDef(netDict):
    groups = []
    for client in netDict['WGNet']['Clients']:
      if ('Group' in client):
        group = client['Group']
        groups.append(group)
    groups = list(dict.fromkeys(groups))
    return groups

def findGroupToCreate(netDict):

    groups = findGroupsInNetworkDef(netDict)
    repeatedGroup = []
    for groupA in groups:
        for groupB in groups:
            if groupA in groupB and groupA != groupB:
                repeatedGroup.append(groupA)
    repeatedGroup = list(dict.fromkeys(repeatedGroup))
    group2create = set(groups) - set(repeatedGroup)
    return group2create

def sortGroups(netDict):

    group2create = findGroupToCreate(netDict)
    subgroup = []
    for group in group2create:
        subgroup.append(group.split("::"))
    sortedSub=sorted(subgroup, key=len)
    return sortedSub

# TODO : Edge Custom Properties
def addEdgeCustomProperties(graph):

    notAvailableWord = ""

    # Protocol: TCP,UDP
    graph.define_custom_property("edge","Protocol","string",notAvailableWord)
    # Src Port[s]
    graph.define_custom_property("edge","SrcPorts","string",notAvailableWord)
    # Dst Port[s]
    graph.define_custom_property("edge","DstPorts","string",notAvailableWord)
    # Action[s]
    graph.define_custom_property("edge","Action","string",notAvailableWord)
    # RaaC
    graph.define_custom_property("edge","RaaC","string",notAvailableWord)

def addNodeCustomProperties(graph):

    notAvailableWord = "NULL"
    # Group,Node,Server,Resource
    graph.define_custom_property("node","Type","string",notAvailableWord)
    # Available for Node,Server,Resource 
    graph.define_custom_property("node","IPAddress","string",notAvailableWord)
    # Only for Server
    graph.define_custom_property("node","PublicIPAddress","string",notAvailableWord)
    # For All
    graph.define_custom_property("node","Name","string",notAvailableWord)
    # For Node,Resource,Server
    graph.define_custom_property("node","Hostname","string",notAvailableWord)
    # Only for the Node,Group
    graph.define_custom_property("node","Group","string",notAvailableWord)
    # Only Node
    graph.define_custom_property("node","UnderControl","string",notAvailableWord)
    # Only Server
    graph.define_custom_property("node","Port","string",notAvailableWord)
    # Only Server
    graph.define_custom_property("node","Subnet","string",notAvailableWord)
    # For Node,Server,Group
    graph.define_custom_property("node","NetworkName","string",notAvailableWord)
    # For Server,Node
    graph.define_custom_property("node","Routes","string",notAvailableWord)
    # COLOR
    graph.define_custom_property("node","COLOR","string",notAvailableWord)


def generateGroupsObject(graph,netDict):
    # Sort groups 
    sortedSub = sortGroups(netDict)
    # Find top parent group
    topParent = []
    for group in sortedSub:
        topParent.append(group[0])
    topParent = list(dict.fromkeys(topParent))

    # a Dictionary which store each group object
    allGroupObject = {}
    description = "Group,{0}".format('Clients')
    allGroupObject['TOP'] = graph.add_group('Clients',description=description)
    for p in topParent:
        groupColor = getRandomColor()
        description = "Group,{0},{1}".format(p,groupColor)
        allGroupObject[p] = allGroupObject['TOP'].add_group(p,description=description,fill=groupColor)

    #print(parentGroupObject)
    # TODO : STORE GROUP COLOR
    # Create group objects
    for groupOuter in sortedSub:
        groupObject = []
        groupObject.append(allGroupObject[groupOuter[0]]) # Find Parent Object
        for groupInner in groupOuter:
            if groupInner in topParent:
                continue
            groupInnerIndex = groupOuter.index(groupInner)
            groupColor = getRandomColor()
            midParentName = '::'.join(groupOuter[0:groupInnerIndex+1])
            description = "Group,{0},{1}".format(midParentName,groupColor) # Group,parent,color
            midParent = groupObject[-1].add_group(groupInner,shape="rectangle",fill=groupColor,description=description)
            groupObject.append(midParent)
            allGroupObject[midParentName] = midParent
    return allGroupObject


def generateGraph(allGroupObject,netDict,graph,clients,graphName,mode='create',WGMode=True):

    
    network = netDict['WGNet']
    networkName = network['Name']
    networkColor = getRandomColor()

    if(WGMode):
        serverProperties = network['Server']
        serverProperties['Type'] = 'Server'
        serverProperties['Subnet'] = network['Subnet']
        serverProperties['NetworkName'] = networkName
        serverProperties['COLOR'] = networkColor
        serverRoutes = network['Server']['Routes']
        
        graph.add_node(serverProperties['Hostname'], shape="roundrectangle", font_style="bolditalic",shape_fill=networkColor,custom_properties=serverProperties)
    else:
        serverProperties = {
            'IPAddress':'1.2.3.4',
            'Type':'Server',
            'NetworkName': networkName,
            'Hostname': 'FW.{0}'.format(networkName),
            'Name': 'FW'

        }
        graph.add_node(serverProperties['Hostname'], shape="roundrectangle", font_style="bolditalic",shape_fill=networkColor,custom_properties=serverProperties)

    for client in clients: # for client in network['Clients']
        clientProperties = client
        if(WGMode and 'Routes' not in clientProperties):
            clientProperties['Routes'] = serverRoutes
        clientProperties['Type'] = 'Client'
        clientProperties['NetworkName'] = networkName
        clientProperties['COLOR'] = networkColor

        if 'Group' in clientProperties:
            clientGroup = clientProperties['Group']
            #groupColor = allGroupObject[clientGroup].fill
            allGroupObject[clientGroup].add_node(clientProperties['Hostname'], shape="ellipse", font_style="plain",custom_properties=clientProperties)  # shape_fill=groupColor
        else:
            # TODO: Check clientProperties['Group'] = 'Clients'
            allGroupObject['TOP'].add_node(clientProperties['Hostname'], shape="ellipse", font_style="plain",custom_properties=clientProperties) #shape_fill=networkColor
    if 'NetworkResources' in netDict:
        for Resource in netDict['NetworkResources']:
            
            resourceProperties = Resource
            resourceColor = getRandomColor()
            resourceProperties['Type']= 'Resource'
            resourceProperties['COLOR'] = resourceColor
            graph.add_node(resourceProperties['Name'],shape='octagon',font_style='italic',shape_fill=getRandomColor(),custom_properties=resourceProperties)
    
    #graph.write_graph('{0}.graphml'.format(graphName))

def exportGraphFile(graph,graphName):
    graph.write_graph('{0}.graphml'.format(graphName))