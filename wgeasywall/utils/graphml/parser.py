import networkx as nx
from tabulate import PRESERVE_WHITESPACE

# Get nodes in a group
def getNodesInGroup(Graph,GroupID,Groups):
    nodesInGroup = []
    for group,nodes in Groups.items():
        if (group.find(GroupID) != -1):
            nodesInGroup = nodesInGroup + nodes
    return nodesInGroup
        

# Read GraphML and return networkx graph
def readGraphML(GraphMLFile):
    G = nx.read_graphml(GraphMLFile)
    return G

# Get All NetworkResources in the Graph
def getNetworkResourceNodes(Graph):

    AllNodeList = Graph.nodes(data=False)
    resources = []

    for node in AllNodeList:
        objectInfo = {}
        if('Type' in Graph.nodes[node] and Graph.nodes[node]['Type'] == 'Resource'):
            objectInfo['Name'] = Graph.nodes[node]['Name']
            objectInfo['NodeID'] = node
            resources.append(objectInfo)
    return resources

# Get a Client (NodeID) in the Network
def getClient(Graph,ClientName):
    return [x for x,y in Graph.nodes(data=True) if 'Name' in y and y['Name']==ClientName and 'Type' in y and y['Type'] == 'Client'][0]

# Get Server
def mapServerIDName(Graph):
    nodesList = Graph.nodes(data=False)
    nodesDict = {}
    for node in nodesList:
        if('Name' not in Graph.nodes[node] ):
            continue
        if(Graph.nodes[node]['Type']!='Server'):
            continue
        nodeName = Graph.nodes[node]['Name']
        nodeID = node 
        nodesDict[nodeName] = nodeID
    return nodesDict


# Get Clients Dict to Map Name and IDs
def mapClientsIDName(Graph):

    nodesList = Graph.nodes(data=False)
    nodesDict = {}
    for node in nodesList:
        if('Name' not in Graph.nodes[node] ):
            continue
        nodeName = Graph.nodes[node]['Name']
        nodeID = node 
        nodesDict[nodeName] = nodeID
    return nodesDict

# Map ResourceName to NodeID in Graph
def mapNetResourcesIDName(Graph):
    netResources = getNetworkResourceNodes(Graph)
    mapDict = {}

    for resource in netResources:
        resName = resource['Name']
        resNodeID = resource['NodeID']

        mapDict[resName] = resNodeID
    return mapDict

# find Group Color
def findGroupColor(Graph):
    NodeList = Graph.nodes(data=False)
    groupColor = {}
    for node in NodeList:
        if 'description' in Graph.nodes[node] and 'Group' in Graph.nodes[node]['description']:
            if('Clients' in Graph.nodes[node]['description']):
                continue
            groupDetail = Graph.nodes[node]['description'].split(',')
            groupColor[groupDetail[1]] = groupDetail[2]
    return groupColor

# Catagorize nodes based on the groups
def findGroup(Graph):

    NodeList = Graph.nodes(data=False)
    parentList = []
    for node in NodeList:
        if 'description' in Graph.nodes[node] and 'Group' in Graph.nodes[node]['description']:
            parentList.append(node)
    parentList = list(dict.fromkeys(parentList))

    groupDict = {}
    for p in parentList:
        groupDict[p] = []

    for node in NodeList:
        if 'Type' in Graph.nodes[node] and Graph.nodes[node]['Type'] == 'Client':
            nodePart = node.split("::")
            parentPart = '::'.join(nodePart[:-1])
            groupDict[parentPart].append(node)

    return groupDict


# Extract group information from the GroupDict
def getGroupInfo(Graph,GroupDict):
    groupsInfo = []
    for group,_ in GroupDict.items():
        groupAttribute = Graph.nodes[group]['description'].split(",")
        groupInfo = {}
        groupInfo['Name'] = groupAttribute[1]
        groupInfo['NodeID'] = group
        groupsInfo.append(groupInfo)
    return groupsInfo

# Extract nodes from group dict
def getNodes(Graph,GroupDict):
    nodesDict = {}
    for group,nodes in GroupDict.items():
        for node in nodes:
            nodeInfoDict = {}
            nodeName = Graph.nodes[node]['Name']
            nodeInfo = Graph.nodes[node]
            nodeId = node
            nodeInfoDict['Name'] = nodeName
            nodeInfoDict['NodeInfo'] = nodeInfo
            nodeInfoDict['NodeID'] = nodeId
            nodesDict[nodeName] = nodeInfoDict
    return nodesDict

# Map GroupName to the NodeID in Graph
def mapGroupsIDName(Graph,GroupDict):

    groupsInfo = getGroupInfo(Graph,GroupDict)
    mapDict = {}
    for group in groupsInfo:
        groupName = group['Name']
        nodeID = group['NodeID']
        mapDict[groupName] = nodeID
    return mapDict

# Get Edges which source or detination of them are Group Node
def getGroupEdgesList(Graph,GroupDict):
    groupEdgeList = []

    for parent,childs in GroupDict.items():

        toGroupEdge = Graph.in_edges(parent)
        fromGroupEdge = Graph.out_edges(parent)

        if (len(toGroupEdge) > 0):
            groupEdgeList.extend(toGroupEdge)
        if (len(fromGroupEdge) > 0):
            groupEdgeList.extend(fromGroupEdge)
    return groupEdgeList

# Get all Edges
def getAllEdgesList(Graph):
    return nx.edges(Graph)


# Get Edges which source or destination of them are a specific Node
def getEdgeToFrom(Graph,NodeID):

    edgeList = []
    toEdge = Graph.in_edges(NodeID)
    fromEdge = Graph.out_edges(NodeID)

    if (len(toEdge) > 0):
        edgeList.extend(toEdge)
    if (len(fromEdge) > 0):
        edgeList.extend(fromEdge)
    return edgeList