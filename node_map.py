# here we need to draw a network graph showing nodes and their connections using networkX
# this will first open the certifying_authority_DB.db in the same directory then query the  -> the QUORUM_NODES table and randomly selecet 5 BASE_METER to map the mapped QUORUM_NODES
# when the it is vlaidated, the edge color must be green and wnhen not valid it must be red

import networkx as nx
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D
import sqlite3 as sqlite

NUMBER_OF_QUERIED_NODES = 1

DB_PATH = "certifying_authority_DB.db"
G = nx.Graph()

def draw_complete_network_graph():
    conn = sqlite.connect(DB_PATH)
    cursor = conn.cursor()
    # Build a MultiGraph so we can represent multiple edges between same node pairs
    MG = nx.MultiGraph()

    base_meters = list()
    cursor.execute("SELECT BASE_METER, QUORUM_NODE, VALIDATED FROM QUORUM_MAP WHERE STAT = 1 ORDER BY RANDOM()")
    rows = cursor.fetchall()
    for row in rows:
        base_meter_id = row[0]
        if base_meter_id in base_meters or len(base_meters) < NUMBER_OF_QUERIED_NODES:
            quorum_node_id = row[1]
            validsted = row[2]
            MG.add_node(base_meter_id, type='BASE_METER')
            MG.add_node(quorum_node_id, type='QUORUM_NODE')
            edge_color = 'green' if validsted == 1 else 'red'
            # add base->quorum edge (may be duplicated if DB contains duplicates)
            MG.add_edge(base_meter_id, quorum_node_id, color=edge_color, peer_edge=False, width=2)
            if base_meter_id not in base_meters:
                base_meters.append(base_meter_id)
        else:
            pass

    for bm in base_meters:
        cursor.execute("SELECT QUORUM_NODE, PEER_NODE, STAT FROM QUORUM_PEERS_MAP WHERE BASE_METER = ? AND STAT = 1", (bm,))
        peer_rows = cursor.fetchall()
        print("Peer rows for base meter", bm, ":", peer_rows)
        for prow in peer_rows:
            quorum_node = prow[0]
            peer_node = prow[1]
            pv = prow[2]
            MG.add_node(peer_node, type='PEER_NODE')
            edge_color = 'green' if pv == 1 else 'red'
            # add quorum->peer edge (allow duplicates)
            MG.add_edge(quorum_node, peer_node, color=edge_color, peer_edge=True, width=1)

    # layout
    pos = nx.spring_layout(MG)

    node_colors = ['orange' if n in base_meters else 'lightblue' for n in MG.nodes()]

    nx.draw_networkx_nodes(MG, pos, node_size=70, node_color=node_colors)

    # Draw parallel edges with slight curvature so duplicates are visible
    # Group edges by undirected node pair
    pair_groups = {}
    for u, v, key, data in MG.edges(keys=True, data=True):
        pair = tuple(sorted((u, v)))
        pair_groups.setdefault(pair, []).append((u, v, key, data))

    for pair, edges in pair_groups.items():
        n = len(edges)
        # radii centered around 0
        if n == 1:
            radii = [0.0]
        else:
            step = 0.2
            radii = [ (i - (n-1)/2) * step for i in range(n) ]
        for (u, v, key, data), rad in zip(edges, radii):
            style = 'dotted' if data.get('peer_edge', False) else 'solid'
            color = data.get('color', 'black')
            width = data.get('width', 1)
            # draw this individual edge with a connectionstyle to create curvature
            nx.draw_networkx_edges(
                MG,
                pos,
                edgelist=[(u, v)],
                edge_color=[color],
                width=width,
                style=style,
                connectionstyle=f"arc3,rad={rad}"
            )
    labels = {n: n for n in MG.nodes()}

    u_labels = {n: labels[n] for n in MG.nodes() if str(n).startswith('u_')}
    other_labels = {n: labels[n] for n in MG.nodes() if not str(n).startswith('u_')}
    nx.draw_networkx_labels(MG, pos, labels=u_labels, font_size=9, font_weight='bold')
    nx.draw_networkx_labels(MG, pos, labels=other_labels, font_size=9, font_weight='normal')

    plt.axis('off')
    plt.title("Network Graph of METER respective QUORU NODES and PEER NODES")
    legend_handles = [
        Line2D([0], [0], color='green', lw=2, linestyle='solid', label='Successful Connection — meter to Quorum node'),
        Line2D([0], [0], color='red', lw=2, linestyle='solid', label='Unsuccessful Connection — meter to Quorum node'),
        Line2D([0], [0], color='green', lw=1, linestyle='dotted', label='Successful Connection — Quorum node to Peer node'),
        Line2D([0], [0], color='red', lw=1, linestyle='dotted', label='Unsuccessful Connection — Quorum node to Peer node'),
    ]
    plt.legend(handles=legend_handles, loc='upper right', frameon=True)
    plt.show()

    conn.close()


def draw_quorum_graph():
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

    edgelist = list(G.edges())
    colors = [G[u][v].get('color', 'black') for u, v in edgelist]
    pos = nx.spring_layout(G)

    node_colors = ['orange' if n in base_meters else 'lightblue' for n in G.nodes()]

    nx.draw_networkx_nodes(G, pos, node_size=70, node_color=node_colors)
    nx.draw_networkx_edges(G, pos, edgelist=edgelist, edge_color=colors, width=2)
    labels = {n: n for n in G.nodes()}

    u_labels = {n: labels[n] for n in G.nodes() if str(n).startswith('u_')}
    other_labels = {n: labels[n] for n in G.nodes() if not str(n).startswith('u_')}
    nx.draw_networkx_labels(G, pos, labels=u_labels, font_size=9, font_weight='bold')
    nx.draw_networkx_labels(G, pos, labels=other_labels, font_size=9, font_weight='normal')

    plt.axis('off')
    plt.title("Network Graph of METER respective QUORUM_NODES")
    legend_handles = [
        Line2D([0], [0], color='green', lw=2, linestyle='solid', label='Successful Connection — meter to Quorum node'),
        Line2D([0], [0], color='red', lw=2, linestyle='solid', label='Unsuccessful Connection — meter to Quorum node'),
    ]
    plt.legend(handles=legend_handles, loc='upper right', frameon=True)

    plt.show()

    conn.close()


if __name__ == "__main__":
    # draw_quorum_graph()
    draw_complete_network_graph()

