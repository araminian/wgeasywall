
from typing import Tuple


def getScore(allEdges,clientsMapID2Name,groupsMapID2Name,networkResourceMapID2Name,nodePriority=1000,resourcePriority=200,groupPriority=100) -> Tuple[list,list]:
    
    edgeScoresID = []
    edgeScoresName = []
    for edge in allEdges:

        srcEdgeID = edge[0]
        dstEdgeID = edge[1]

        if (srcEdgeID in groupsMapID2Name):
            srcPriority = groupPriority
            srcName = groupsMapID2Name[srcEdgeID]
        if (srcEdgeID in clientsMapID2Name):
            srcPriority = nodePriority
            srcName = clientsMapID2Name[srcEdgeID]
        if (srcEdgeID in networkResourceMapID2Name):
            srcPriority = resourcePriority
            srcName = networkResourceMapID2Name[srcEdgeID]
        
        if (dstEdgeID in groupsMapID2Name):
            dstPriority = groupPriority
            dstName = groupsMapID2Name[dstEdgeID]
        if (dstEdgeID in clientsMapID2Name):
            dstPriority = nodePriority
            dstName = clientsMapID2Name[dstEdgeID]
        if (dstEdgeID in networkResourceMapID2Name):
            dstPriority = resourcePriority
            dstName = networkResourceMapID2Name[dstEdgeID]
        
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
        edgeScoresID.append((srcEdgeID,dstEdgeID,score))
        edgeScoresName.append((srcName,dstName,score))
        
        edgeScoresName.sort(key=lambda tup: tup[2],reverse=True)
        edgeScoresID.sort(key=lambda tup: tup[2],reverse=True)
    return (edgeScoresID,edgeScoresName)