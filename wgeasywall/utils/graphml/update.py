import random
import networkx as nx
import wgeasywall.utils.graphml.parser as parser
import wgeasywall.utils.parse.diffdetector as diffdetector

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

def updateGroupsObject(graph,netDict,groupsColor):
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
        if p in groupsColor:
            groupColor = groupsColor[p]
        else:
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
            midParentName = '::'.join(groupOuter[0:groupInnerIndex+1])
            if midParentName in groupsColor:
                groupColor = groupsColor[midParentName]
            else:
                groupColor = getRandomColor()
            
            description = "Group,{0},{1}".format(midParentName,groupColor) # Group,parent,color
            midParent = groupObject[-1].add_group(groupInner,shape="rectangle",fill=groupColor,description=description)
            groupObject.append(midParent)
            allGroupObject[midParentName] = midParent
    return allGroupObject

def getEdges2Draw(graphFile,newNetworkDefinition,oldNetworkDefinition):

    graph = nx.read_graphml(graphFile)
    newNetDif = newNetworkDefinition
    oldNetDif = oldNetworkDefinition

    net = newNetDif['WGNet']['Name']
    nodes = graph.nodes(data=False)
    groups = parser.findGroup(graph)
    groupsColor = parser.findGroupColor(graph)
    

    groupInfo = parser.getGroupInfo(graph,groups)
    networkResource = parser.getNetworkResourceNodes(graph)

    allEdges = parser.getAllEdgesList(graph)

    clientsMapName2ID = parser.mapClientsIDName(graph)
    groupsMapName2ID = parser.mapGroupsIDName(graph,groups)
    networkResourceMapName2ID = parser.mapNetResourcesIDName(graph)

    clientsMapID2Name = dict((v,k) for k,v in clientsMapName2ID.items())
    groupsMapID2Name = dict((v,k) for k,v in groupsMapName2ID.items())
    networkResourceMapID2Name = dict((v,k) for k,v in networkResourceMapName2ID.items())

    clientResult = diffdetector.getNetDiff(newNetDif,oldNetDif,net,'Clients')
    networkResourceResult = diffdetector.getNetDiff(newNetDif,oldNetDif,net,'NetworkResources')

    clientsRemoved = diffdetector.detectRemovedItem(clientResult)
    networkResourcesRemoved = diffdetector.detectRemovedItem(networkResourceResult)

    EdgeRemoved = []

    for client in clientsRemoved:

        clientName = client['ObjectName']
        clientNodeID = clientsMapName2ID[clientName]

        EdgeRemoved.extend(parser.getEdgeToFrom(graph,clientNodeID))
    
    for netRes in networkResourcesRemoved:

        netResName = netRes['ObjectName']
        netResID = networkResourceMapName2ID[netResName]

        EdgeRemoved.extend(parser.getEdgeToFrom(graph,netResID))

    groupOld = findGroupToCreate(oldNetDif)
    groupNew =  findGroupToCreate(newNetDif)
    groupsRemoved = list(set(groupOld) - set(groupNew))

    for removedGroup in groupsRemoved:
        groupId = groupsMapName2ID[removedGroup]
        EdgeRemoved.extend(parser.getEdgeToFrom(graph,groupId))

    EdgeRemoved = list(dict.fromkeys(EdgeRemoved))

    # print("ALL EDGES")
    # print(allEdges)
    # print("EDGE to Remove")
    # print(EdgeRemoved)
    # print("EDGE TO DRAW ID")
    edgeToDrawID = allEdges - EdgeRemoved
    # print(edgeToDrawID)
        
    edgeToDrawName = []
    allMapID2Name = {**clientsMapID2Name,**groupsMapID2Name,**networkResourceMapID2Name}
    edgeToDrawIDList = []
    for edge in edgeToDrawID:

        src = edge[0]
        dst = edge[1]
        edgeToDrawIDList.append((src,dst))
        srcName = allMapID2Name[src]
        dstName = allMapID2Name[dst]
        edgeToDrawName.append((srcName,dstName))
    
    return (edgeToDrawName,groupsColor,edgeToDrawIDList)

def addEdges(graph,edgeToDrawName,mapName2Hostname,edgeToDrawID,nxGraph):
    
    for edge in edgeToDrawName:
        index = edgeToDrawName.index(edge)
        srcID = edgeToDrawID[index][0]
        dstID = edgeToDrawID[index][1]
        edgeAttributes = nxGraph.get_edge_data(srcID,dstID)
        src = edge[0]
        dst = edge[1]
        if ('::' in src):
            src = src.split('::')[-1]
        if ('::' in dst):
            dst = dst.split('::')[-1]
        
        if (src in mapName2Hostname):
            src = mapName2Hostname[src]
        if (dst in mapName2Hostname):
            dst = mapName2Hostname[dst]
        edgeAttributes.pop('id', None)
        graph.add_edge(src,dst,custom_properties=edgeAttributes)

def getResourcesAndClients(networkDefiDict):
    items = []

    for client in networkDefiDict['WGNet']['Clients']:
        items.append(client['Name'])
    for resource in networkDefiDict['NetworkResources']:
        items.append(resource['Name'])
    
    return items

def checkRemovedNodeInEdge(clientsAndResources,edgeToDrawName,edgeToDrawID):

    edge2Draw = []
    edge2DrawID = []

    for edge in edgeToDrawName:

        index=edgeToDrawName.index(edge)

        srcID = edgeToDrawID[index][0]
        dstID = edgeToDrawID[index][1]

        src = edge[0]
        dst = edge[1]

        if ('::' in src and '::' in dst):
            continue
        if( '::' not in src and src not in clientsAndResources and src != 'Clients'):
            continue
        if ('::' not in dst and dst not in clientsAndResources and dst != 'Clients'):
            continue
        edge2Draw.append((src,dst))
        edge2DrawID.append((srcID,dstID))
    return edge2Draw,edge2DrawID
