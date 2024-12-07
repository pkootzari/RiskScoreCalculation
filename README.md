# Risk Score Calculation in Multi-layer Attack Graphs

This is the repository containing the code and the artifacts of the project for Course SYSC5500.

## Scenarios

All the scnearios are inside scnearios folder. Inside the folders you can see how they are grouped based on the number of layers and percentage of vulnerable containers.

Eech scenario needs two files as input. 
 
 - topology.json: This file contains the information about the connectivity and type of the relationship between nodes.
    - 1: This is the network relationship
    - 2: This is the hosting relationship between a container and a VM
    - 4: This is the hosting relationship betwene a VM and a physical host
 - CVEassignment.json: This files contains the CVE that is assigned to each node. Each CVE record must have the CVSS metrics for probablity calculation and the type of the CVE that shows through what kind of connections the CVE can be exploited (1 is for network, 2 is for container escape and 4 is for VM escape.)

## List of Vulnerabilities

List of all the vulnerabilities that we used in our experiments are inside CVEsource.json. We extracted important information from them and saved a lightweight version of the vulnerabilites inside CVEfeedMod.json.
The vulnerabiliteis inside this file are the ones that later assigned to each node in the topology.

## How to Run

bayesian_calcualtor.py is the file that does the calculation. It only reqires the path to the scneario and it expects to see topology.json and CVEassignment.json files inside the scenario folder. After doing the calculation it creates attack_graph_bfs_final.dot and attack_graph_bfs_final.dot.png that visualize the final attack graph alongside the calculated metrics for each node. The calculated risk score for each node is also stored inside results.json file.

```bash
python bayesian_calculator.py scenarios/netflix/thirty_percent_vul/three_layer
```

The other file is results_aggregator.py which collects all the results from all different scenrios and store them inside aggregated_results.json.

```bash
python results_aggregator.py scenarios/netflix
```

