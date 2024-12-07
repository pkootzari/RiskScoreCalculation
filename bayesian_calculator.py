import os
import json
from queue import Queue
import graph_utils
import pydot
import writer
import argparse
import random
import copy


# SCENARIOS_FOLDER = "scenarios"
TOPOLOGY_FILE_NAME = "topology.json"
CVE_ASSIGNMENT = "CVEassignment.json"
# ATTACK_GRAPH_FILE = "attack_graph.dot"
# ATTACK_GRAPH_WITH_PROB = "attack_graph_final.dot"
SCENARIO_FOLDER = None


def get_nodes(graph):
    nodes = set([])
    for node, neighbors in graph.items():
        if node not in nodes:
            nodes.add(node)
        for neighbor in neighbors:
            if neighbor not in nodes:
                nodes.add(neighbor)
    
    return nodes


def read_assigned_cves(file_name="CVEassignment.json"):
    with open(os.path.join(SCENARIO_FOLDER, file_name), 'r') as file:
        data = json.load(file)
    return data


def generate_parents_dict(graph, node_list):
    parents_dict = {}

    for node, neighbors in graph.items():
        for neighbor, label in neighbors.items():
            if neighbor in parents_dict:
                if node not in parents_dict[neighbor]:
                    parents_dict[neighbor][node] = label
                else:
                    print(f"edge {node}, {neighbor} is already added to the parent graph with label {label}")
            else:
                parents_dict[neighbor] = {node: label}

    for node in node_list:
        if node not in parents_dict:
            parents_dict[node] = {}

    return parents_dict


def calculate_union_p(list_of_probabiliites):
    """
    This function assumes there is OR relationship between probabilities
    """
    P_all_false = 1
    for prob in list_of_probabiliites:
        P_all_false *= (1-prob)
    
    return 1 - P_all_false


def calculate_score(graph, nodes_probs, source="attacker"):
    """
    graph has to be in this format:
    {
        node1: {
            node2: probability,
            node3: probability,
            ...
        },
        ...
    }
    """


    if graph_utils.has_cycle(graph):
        print("The calculation can't be done because the input graph has cycles")
        return
    
    # now let's start calculating the beysian score
    nodes = nodes_probs.keys()
    parents_dict = generate_parents_dict(graph, nodes)
    assigned_cves = read_assigned_cves()
    cum_probabilities = {}

    # initialize the probabilites for nodes with no parents
    for node in nodes:
        if node == source:
            cum_probabilities[source] = 1
            continue
        if len(parents_dict[node].keys()) == 0:
            cum_probabilities[node] = 0


    while len(nodes) != len(cum_probabilities):
        # do bfs
        changed = False
        queue = Queue()
        queue.put(source)
        
        while not queue.empty():
            current_node = queue.get()

            if current_node in cum_probabilities:
                for neighbor in graph[current_node]:
                    queue.put(neighbor)
                continue

            current_node_parents = parents_dict[current_node].keys()
            ready_to_calculate = True
            for parent in current_node_parents:
                if parent not in cum_probabilities:
                    ready_to_calculate = False
            if ready_to_calculate:
                # calculate P of all values in their parents
                parent_probs = [cum_probabilities[parent] for parent in parents_dict[current_node]]
                parents_union_p = calculate_union_p(parent_probs)
                current_node_prob = assigned_cves[current_node][0]['prob'] if len(assigned_cves[current_node]) == 1 else assigned_cves[current_node][1]['prob']
                nodes_probs[current_node] = current_node_prob

                cum_probabilities[current_node] = parents_union_p * current_node_prob
                cum_probabilities[current_node] = round(cum_probabilities[current_node], 5)
                changed = True
            
            for neighbor in graph[current_node]:
                queue.put(neighbor)
        
        if not changed and len(cum_probabilities) != len(nodes):
            print("Seems like the algorithm can't infer score for some of the nodes")
            print(cum_probabilities)
            return cum_probabilities
    
    return cum_probabilities


def check_edge_exists(src, dst, topology):
    if src in topology:
        if dst in topology[src]:
            return True
    return False


def add_edge_to_attack_graph(src, dst, attack_graph_topology, edge_label):
    # we have to check if the dst -> src edge already exists or not
    if check_edge_exists(dst, src, attack_graph_topology):
        return attack_graph_topology
    
    
    # add the edge to the copy of topoloyg if it didn't create any new cycles then we can proceed and add the edge to the actual topology
    attack_graph_topology_copy = copy.deepcopy(attack_graph_topology)
    
    if src in attack_graph_topology_copy:
        if dst in attack_graph_topology_copy[src]:
            print(f"edge {src} and {dst} already exists with probability {attack_graph_topology_copy[src][dst]}!")
        else:
            attack_graph_topology_copy[src][dst] = edge_label
    else:
        attack_graph_topology_copy[src] = {dst: edge_label}

    
    if graph_utils.has_cycle(attack_graph_topology_copy):
        print(f"edge {src} and {dst} causes cycles so it is not added!")
    else:
        attack_graph_topology = copy.deepcopy(attack_graph_topology_copy)
    
    return attack_graph_topology


# def add_nodes_with_no_exit_edge(graph, nodes):
#     for node in nodes:
#         if node not in graph:
#             graph[node] = {}
#     return graph


def check_if_CVE_list_has_specific_type(CVE_list, type):
    for cve in CVE_list:
        if cve['type'] == type:
            return True
    
    return False


def generate_attack_graph_by_bfs(topology, node_list, assigned_cves, source="attacker"):
    queue = Queue()
    queue.put("attacker")
    seen_nodes = set(["attacker"])

    attack_graph_topology = {}

    while not queue.empty():
        current_node = queue.get()

        for neighbor, connection_type in topology[current_node].items():
            if neighbor == source:
                continue
            
            reached = False
            if connection_type in [1, 2, 4]:
                if check_if_CVE_list_has_specific_type(assigned_cves[neighbor], connection_type):
                    attack_graph_topology = add_edge_to_attack_graph(current_node, neighbor, attack_graph_topology, connection_type)
                    reached = True
            elif connection_type in [3, 5]:
                if check_if_CVE_list_has_specific_type(assigned_cves[neighbor], 1):
                    attack_graph_topology = add_edge_to_attack_graph(current_node, neighbor, attack_graph_topology, connection_type)
                    reached = True
            else:
                print("The connection type is none of the above which is wrong!")
            
            if reached:
                if neighbor not in seen_nodes:
                    seen_nodes.add(neighbor)
                    queue.put(neighbor)
            
    for node in node_list:
        if node not in attack_graph_topology:
            attack_graph_topology[node] = {}

    return attack_graph_topology


def generate_attack_graph_by_dfs(topology, node_list, assigned_cves, source="attacker"):
    visited = set()
    stack = []

    attack_graph_topology = {}
    # initialize the attack_graph_topology
    for node in node_list:
        attack_graph_topology[node] = {}

    def DFS(current_node):
        visited.add(current_node)
        stack.append(current_node)

        for neighbor in topology[current_node]:
            if neighbor == source:
                continue

            connection_type = topology[current_node][neighbor]

            # check if the neighbor actually has exploitable CVE
            if connection_type in [1, 2, 4]:   # the network, cotainer to VM and VM to host CVEs
                if not check_if_CVE_list_has_specific_type(assigned_cves[neighbor], connection_type):
                    continue
            elif connection_type in [3, 5]:    # the VM to container and physical host to VM which we consider as network CVEs
                if not check_if_CVE_list_has_specific_type(assigned_cves[neighbor], 1):
                    continue
            else:
                print("The connection type is none of the above which is wrong!")
                raise Exception


            if neighbor not in visited:
                # add the edge
                if neighbor in attack_graph_topology[current_node]:
                    print(f"edge {current_node} and {neighbor} already exists in the attack graph topology!")
                else:
                    attack_graph_topology[current_node][neighbor] = connection_type

                DFS(neighbor)

            elif neighbor in visited and neighbor not in stack:
                # add the edge (this is a forward edge)
                if neighbor in attack_graph_topology[current_node]:
                    print(f"edge {current_node} and {neighbor} already exists in the attack graph topology!")
                else:
                    connection_type = topology[current_node][neighbor]
                    attack_graph_topology[current_node][neighbor] = connection_type


        stack.pop()

    DFS(source)
    return attack_graph_topology


def create_dot_file_from_topology_with_node_scores(input_graph, nodes_prob, noded_cum_probabilities, output_file):
    """
    The format of graph is the same as other functions
    socers is a dict:
    {
        node1: score,
        node2: score,
        ...
    }
    """
    graph_type = "digraph" # it's always supposed to be directed
    graph = pydot.Dot(graph_type=graph_type)

    # Add nodes based on the probabilities
    nodes = get_nodes(input_graph)
    for node in nodes:
        graph.add_node(pydot.Node(node, label=f"{node} | {nodes_prob[node]} | {noded_cum_probabilities[node]}"))

    # Add edges based on the adjacency matrix
    for node, neighbors in input_graph.items():
        for neighbor, label in neighbors.items():
            edge = pydot.Edge(node, neighbor, label=label)
            graph.add_edge(edge)

    # Write the graph to a DOT file
    graph.write(output_file)
    graph.write_png(output_file+".png")
    print(f"DOT file written to {output_file}")


def load_topology(file_path, file_name):
    with open(os.path.join(file_path, file_name), 'r') as file:
        data = json.load(file)
    return data['nodes_prob'], data['adjacency_matrix']


def main(directory):
    global SCENARIO_FOLDER
    SCENARIO_FOLDER = directory

    working_directory = os.path.join(directory)

    nodes_prob, adjacency_matrix = load_topology(working_directory, "topology.json")

    with open(os.path.join(working_directory, "CVEassignment.json"), 'r') as file:
        assigned_cves = json.load(file)

    # first time with bfs
    attack_graph_topology = generate_attack_graph_by_bfs(adjacency_matrix, nodes_prob.keys(), assigned_cves)
    
    with open(os.path.join(working_directory, "attack_graph_bfs.json"), 'w') as json_file:
        json.dump(attack_graph_topology, json_file, indent=4)

    writer.graph_to_dot(attack_graph_topology, os.path.join(working_directory, "attack_graph_bfs.dot"))

    cum_probabilites = calculate_score(attack_graph_topology, nodes_prob)
    create_dot_file_from_topology_with_node_scores(attack_graph_topology, nodes_prob, cum_probabilites, os.path.join(working_directory, 'attack_graph_bfs_final.dot'))
    writer.write_cum_probability_resutls({'cumulative_probs_bfs': cum_probabilites}, directory)

    
    # second time with dfs
    attack_graph_topology = generate_attack_graph_by_dfs(adjacency_matrix, nodes_prob.keys(), assigned_cves)
    
    with open(os.path.join(working_directory, "attack_graph_dfs.json"), 'w') as json_file:
        json.dump(attack_graph_topology, json_file, indent=4)

    writer.graph_to_dot(attack_graph_topology, os.path.join(working_directory, "attack_graph_dfs.dot"))

    cum_probabilites = calculate_score(attack_graph_topology, nodes_prob)
    create_dot_file_from_topology_with_node_scores(attack_graph_topology, nodes_prob, cum_probabilites, os.path.join(working_directory, 'attack_graph_dfs_final.dot'))
    writer.write_cum_probability_resutls({'cumulative_probs_dfs': cum_probabilites}, directory)


if __name__ == "__main__":
    # Create the parser
    parser = argparse.ArgumentParser(
        description="The main program for doing bayesian calcualtion."
    )

    # Add positional arguments
    parser.add_argument("scenario_folder", type=str, help="Name of the scenario folder")
    # parser.add_argument("cve_source_file", type=str, help="Path to the input file")
    # parser.add_argument("output_file", type=str, help="Path to the output file", default="CVEfeed.json")

    # Parse arguments
    args = parser.parse_args()

    # Access parsed arguments
    print(f"scenario_folder: {args.scenario_folder}")
    # print(f"cve_source_file: {args.cve_source_file}")
    # print(f"output_file: {args.output_file}")

    main(args.scenario_folder)