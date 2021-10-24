from networkx.readwrite.edgelist import parse_edgelist
import typer
from pathlib import Path
import networkx as nx
import wgeasywall.utils.graphml.parser as parser
from wgeasywall.utils.IPtable.ipset import generateIPSetScript


app = typer.Typer()

@app.command()
def generate(
    graphFile: Path = typer.Option(...,"--graph-file",help="The GraphML file")
):
    if not graphFile.is_file():
        typer.echo("ERROR: GraphML file can't be found!",err=True)
        raise typer.Exit(code=1)

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

    test = parser.getNodesInGroup(graph,'n4::n1',groups)
    
    # Create IPSet
    createdIPSet = {}
    for edge in allEdges:

        srcEdgeID = edge[0]
        dstEdgeID = edge[1]
        
        srcEdgeName = groupsMapID2Name[srcEdgeID]
        dstEdgeName = groupsMapID2Name[dstEdgeID]

        # Check if  the src or dst are group
        if (srcEdgeName not in createdIPSet  and srcEdgeID in groupsMapID2Name):
            nodesOfSrcGroup = parser.getNodesInGroup(graph,srcEdgeID,groups)

            IPsInIPSet = []
            for node in nodesOfSrcGroup:
                IPsInIPSet.append(str(graph.nodes[node]['IPAddress']))
            createdIPSet[srcEdgeName] = IPsInIPSet

        if (dstEdgeName not in createdIPSet and dstEdgeID in groupsMapID2Name):
            nodesOfDstGroup = parser.getNodesInGroup(graph,dstEdgeID,groups)
            
            IPsInIPSet = []
            for node in nodesOfDstGroup:
                IPsInIPSet.append(str(graph.nodes[node]['IPAddress']))
            createdIPSet[dstEdgeName] = IPsInIPSet

    generateIPSetScript(createdIPSet)     
    


