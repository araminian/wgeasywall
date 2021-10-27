from os import error
from sys import argv
from networkx.readwrite.edgelist import parse_edgelist
import typer
from pathlib import Path
import networkx as nx
import wgeasywall.utils.graphml.parser as parser
from wgeasywall.utils.IPtable.ipset import generateIPSetScript
from wgeasywall.utils.IPtable.score import getScore
from wgeasywall.utils.IPtable.rule import generateActionSyntax, generateFunctionSyntax, generateRaaC
from wgeasywall.utils.ruleAsCode.generate import createRules, migrateToNFT

app = typer.Typer()

@app.command()
def generate(
    graphFile: Path = typer.Option(...,"--graph-file",help="The GraphML file")
):
    if not graphFile.is_file():
        typer.echo("ERROR: GraphML file can't be found!",err=True)
        raise typer.Exit(code=1)
    nft = False
    # Parse graph
    graph = nx.read_graphml(graphFile)
    groups = parser.findGroup(graph)

    # Get all edges
    allEdges = parser.getAllEdgesList(graph)

    # Maps
    clientsMapName2ID = parser.mapClientsIDName(graph)
    groupsMapName2ID = parser.mapGroupsIDName(graph,groups)
    networkResourceMapName2ID = parser.mapNetResourcesIDName(graph)

    clientsMapID2Name = dict((v,k) for k,v in clientsMapName2ID.items())
    groupsMapID2Name = dict((v,k) for k,v in groupsMapName2ID.items())
    networkResourceMapID2Name = dict((v,k) for k,v in networkResourceMapName2ID.items())

    # Create IPSet
    createdIPSet = {}
    for edge in allEdges:

        srcEdgeID = edge[0]
        dstEdgeID = edge[1]
        
        
        # Check if  the src or dst are group
        if (srcEdgeID in groupsMapID2Name):
            srcEdgeName = groupsMapID2Name[srcEdgeID]
            if (srcEdgeName not in createdIPSet):
                nodesOfSrcGroup = parser.getNodesInGroup(graph,srcEdgeID,groups)

                IPsInIPSet = []
                for node in nodesOfSrcGroup:
                    IPsInIPSet.append(str(graph.nodes[node]['IPAddress']))
                createdIPSet[srcEdgeName] = IPsInIPSet
        if (dstEdgeID in groupsMapID2Name):
            dstEdgeName = groupsMapID2Name[dstEdgeID]
            if (dstEdgeName not in createdIPSet):
                nodesOfDstGroup = parser.getNodesInGroup(graph,dstEdgeID,groups)
                
                IPsInIPSet = []
                for node in nodesOfDstGroup:
                    IPsInIPSet.append(str(graph.nodes[node]['IPAddress']))
                createdIPSet[dstEdgeName] = IPsInIPSet

    generateIPSetScript(createdIPSet)     
    
    edgeScoreID , edgeScoreName = getScore(allEdges,clientsMapID2Name,groupsMapID2Name,networkResourceMapID2Name)
    IPtableRules = []
    for edge in edgeScoreID:
        index = edgeScoreID.index(edge)
        edgeN = edgeScoreName[index]
        
        # Get Attributes of a edge to determine use normal way or special RaaC
        srcEdgeID = edge[0]
        dstEdgeID = edge[1]
        srcType = edge[3]
        dstType = edge[4]
        edgeAttributes = graph.get_edge_data(srcEdgeID,dstEdgeID)
        # Special way 
        if ('RaaC' in edgeAttributes):
            specialRaaCs = edgeAttributes['RaaC'].split(',')
            argumentsToInject = {}
            if(srcType == 'Group'):
                srcSetName = srcEdgeName.replace("::","-")
                argumentsToInject['srcSet'] = "WGEasywall-{0}".format(srcSetName)
            elif(srcType=='Node'):
                argumentsToInject['srcIP'] = graph.nodes[srcEdgeID]['IPAddress']
            # TODO Type Network Resource

            if (dstType == 'Group'):
                dstSetName = dstEdgeName.replace("::","-")
                argumentsToInject['dstSet'] = "WGEasywall-{0}".format(dstSetName)
            elif(dstType == 'Node'):
                argumentsToInject['dstIP'] = graph.nodes[dstEdgeID]['IPAddress']

            comment= "WGEasywall generated rule for edge from {0} to {1}".format(srcEdgeName.replace("::","-"),dstEdgeName.replace("::","-"))
            argumentsToInject['comment'] = "'{0}'".format(comment)

            for sRaaC in specialRaaCs:

                ruleEnd = createRules(
            function=sRaaC,
            actionVersion='@latest',
            functionVersion='@latest',
            injectArgumets=argumentsToInject
            )

                if (type(ruleEnd) == dict):
                    IPtableRules.append((sRaaC,ruleEnd['ErrorMsg']))
                
                for rule in ruleEnd:
                    rule2show = ' '.join(rule)
                    if (not nft):
                        IPtableRules.append((sRaaC,rule2show))
                    else:
                        nftRule = migrateToNFT(rule2show)
                        nftRuleComponents = nftRule.split(" ")
                        desiredIndex = nftRuleComponents.index("FORWARD")
                        IPtableRules.append((sRaaC,' '.join(nftRuleComponents[desiredIndex+1:])))
            continue
        
        # Normal Way
        functionArgument = generateFunctionSyntax(graph,edge,edgeN)
        
        actionList = generateActionSyntax(graph,edge,edgeN)
        

        errorFlag = False
        if (type(actionList) == dict and 'ErrorCode' in actionList):
            errorFlag = True
            typer.echo("ERROR: {0}".format(actionList['ErrorMsg']))
        if (type(functionArgument) == dict and 'ErrorCode' in functionArgument):
            typer.echo("ERROR: {0}".format(functionArgument['ErrorMsg']))
            errorFlag = True

        if (errorFlag):
            continue

        RaaCList = generateRaaC(actionList,functionArgument)
        #print(RaaCList[0])
        
        
        for generatedRule in RaaCList:

            ruleEnd = createRules(
            function=generatedRule,
            actionVersion='@latest',
            functionVersion='@latest'
            )

            if (type(ruleEnd) == dict):
                IPtableRules.append((generatedRule,ruleEnd['ErrorMsg']))
    
            for rule in ruleEnd:
                rule2show = ' '.join(rule)
                if (not nft):
                    IPtableRules.append((generatedRule,rule2show))
                else:
                    nftRule = migrateToNFT(rule2show)
                    nftRuleComponents = nftRule.split(" ")
                    desiredIndex = nftRuleComponents.index("FORWARD")
                    IPtableRules.append((generatedRule,' '.join(nftRuleComponents[desiredIndex+1:])))
        
    for iRule in IPtableRules:
        print(iRule[0])
        print()
        print(iRule[1])
        print("-------------------")
