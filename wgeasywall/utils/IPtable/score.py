
from typing import Tuple

from networkx.generators.trees import prefix_tree


def getScore(allEdges,clientsMapID2Name,groupsMapID2Name,networkResourceMapID2Name,serverMapID2Name,nodePriority=1000,resourcePriority=200,groupPriority=100) -> Tuple[list,list]:
    
    edgeScoresID = []
    edgeScoresName = []
    for edge in allEdges:
        srcEdgeID = edge[0]
        dstEdgeID = edge[1]
        srcType = ""
        dstType = ""
        if (srcEdgeID in groupsMapID2Name):
            srcPriority = groupPriority
            srcName = groupsMapID2Name[srcEdgeID]
            srcType = "Group"
        if (srcEdgeID in clientsMapID2Name):
            srcPriority = nodePriority
            srcName = clientsMapID2Name[srcEdgeID]
            srcType = "Node"
        if (srcEdgeID in networkResourceMapID2Name):
            srcPriority = resourcePriority
            srcName = networkResourceMapID2Name[srcEdgeID]
            srcType = "Resource"
        if (srcEdgeID in serverMapID2Name):
            srcPriority = resourcePriority
            srcName = serverMapID2Name[srcEdgeID]
            srcType = "Server"

        if (dstEdgeID in groupsMapID2Name):
            dstPriority = groupPriority
            dstName = groupsMapID2Name[dstEdgeID]
            dstType = "Group"
        if (dstEdgeID in clientsMapID2Name):
            dstPriority = nodePriority
            dstName = clientsMapID2Name[dstEdgeID]
            dstType = "Node"
        if (dstEdgeID in networkResourceMapID2Name):
            dstPriority = resourcePriority
            dstName = networkResourceMapID2Name[dstEdgeID]
            dstType = "Resource"
        if (dstEdgeID in serverMapID2Name):
            dstPriority = resourcePriority
            dstName = serverMapID2Name[dstEdgeID]
            dstType = "Server"
        srcDepth = srcEdgeID.count("::") + 1
        dstDepth = dstEdgeID.count("::") + 1

        score = (srcPriority * srcDepth) + (dstPriority * dstDepth)

        # print("--------------------")
        # print("srcName   ",srcName)
        # print("dstName   ",dstName)
        # print("srcID   ",srcEdgeID)
        # print("dstID  ",dstEdgeID)
        # print("srcP   ",srcPriority)
        # print("dstP  ",dstPriority)
        # print("srcDep  ",srcDepth)
        # print("dstDep  ",dstDepth)
        # print("Score ", score )
        # print("--------------------")
        edgeScoresID.append((srcEdgeID,dstEdgeID,score,srcType,dstType))
        edgeScoresName.append((srcName,dstName,score,srcType,dstType))
        
        edgeScoresName.sort(key=lambda tup: tup[2],reverse=True)
        edgeScoresID.sort(key=lambda tup: tup[2],reverse=True)
    return (edgeScoresID,edgeScoresName)