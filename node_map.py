# here we need to draw a network graph showing nodes and their connections using networkX
# this will first open the certifying_authority_DB.db in the same directory then query the  -> the QUORUM_NODES table and randomly selecet 5 BASE_METER to map the mapped QUORUM_NODES
# when the it is vlaidated, the edge color must be green and wnhen not valid it must be red

import networkx as nx
import matplotlib.pyplot as plt
import sqlite3 as sqlite

NUMBER_OF_QUERIED_NODES = 1

DB_PATH = "certifying_authority_DB.db"
G = nx.Graph()
def draw_network_graph():
    # try:
    conn = sqlite.connect(DB_PATH)
    cursor = conn.cursor()

    base_meters = list()
    cursor.execute("SELECT BASE_METER, QUORUM_NODE, VALIDATED FROM QUORUM_MAP WHERE STAT = 1 ORDER BY RANDOM()")
    rows = cursor.fetchall()
    for row in rows:
        base_meter_id = row[0]
        # print(base_meter_id)
        if base_meter_id in base_meters or len(base_meters)<NUMBER_OF_QUERIED_NODES:
            quorum_node_id = row[1]
            validsted = row[2]
            G.add_node(base_meter_id, type='BASE_METER')
            G.add_node(quorum_node_id, type='QUORUM_NODE')
            edge_color = 'green' if validsted == 1 else 'red'
            G.add_edge(base_meter_id, quorum_node_id, color=edge_color)
            if base_meter_id not in base_meters:
                base_meters.append(base_meter_id)
        else:
            pass 
    # print(base_meters)       
    
    edgelist = list(G.edges())
    colors = [G[u][v].get('color', 'black') for u, v in edgelist]
    pos = nx.spring_layout(G)
    # Color nodes grey only if their id is present in the base_meters list
    node_colors = ['grey' if n in base_meters else 'lightblue' for n in G.nodes()]
    # draw nodes and edges separately so we can style labels individually
    nx.draw_networkx_nodes(G, pos, node_size=70, node_color=node_colors)
    nx.draw_networkx_edges(G, pos, edgelist=edgelist, edge_color=colors, width=2)
    labels = {n: n for n in G.nodes()}
    # bold labels for nodes starting with 'u_'
    u_labels = {n: labels[n] for n in G.nodes() if str(n).startswith('u_')}
    other_labels = {n: labels[n] for n in G.nodes() if not str(n).startswith('u_')}
    nx.draw_networkx_labels(G, pos, labels=u_labels, font_size=9, font_weight='bold')
    nx.draw_networkx_labels(G, pos, labels=other_labels, font_size=9, font_weight='normal')
    # remove axes/frame around the diagram
    plt.axis('off')
    plt.title("Network Graph of METER respective QUORUM_NODES")
    plt.show()
        
    conn.close()
    # except Exception as e:
    #     print("Error drawing network graph:", e)


if __name__ == "__main__":
    draw_network_graph()

