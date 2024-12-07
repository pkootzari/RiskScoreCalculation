import argparse
import json
import os
import csv


def read_json(file_path):
    with open(file_path, 'r') as file:
        data = json.load(file)
    return data


def write_json(file_path, data):
    with open(file_path, 'w') as json_file:
        json.dump(data, json_file, indent=4)


def aggregate_results(directory):
    results = {}

    current_directory = directory
    
    # check if the current directory has subdirectories or not
    if any(os.path.isdir(os.path.join(current_directory, entry)) for entry in os.listdir(current_directory)):
        sub_directories = [entry for entry in os.listdir(current_directory) if os.path.isdir(os.path.join(current_directory, entry))]
        for sub_dir in sub_directories:
            results[sub_dir] = aggregate_results(os.path.join(current_directory, sub_dir))
        return results

    # When we reach the actual forlder for the scenarios
    scenario_results = read_json(os.path.join(current_directory, "results.json"))
    return scenario_results['cumulative_probs_bfs']


if __name__ == "__main__":
    # Create the parser
    parser = argparse.ArgumentParser(
        description="This program aggregates all the results and writes them into a csv file."
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

    results = aggregate_results(args.scenario_folder)
    write_json(os.path.join(args.scenario_folder, "aggregated_results.json"), results)


    new_res = {}
    for percetage in results:
        for num_of_layers in results[percetage]:
            partial_results = {key: value for key, value in results[percetage][num_of_layers].items() if key not in ["C1_VM1", "C2_VM1", "C1_VM2", "C2_VM2", "PH1", "PH2", "attacker"]}
            new_res[f"{percetage}-{num_of_layers}"] = dict(sorted(partial_results.items()))

    write_json(os.path.join(args.scenario_folder, "new_aggregated_results.json"), new_res)

    csv_file = "output_results.csv"

    # Writing the dictionary to a CSV file
    with open(os.path.join(args.scenario_folder, csv_file), mode="w", newline="") as file:
        writer = csv.writer(file)

        # Write the header row (keys of the first sub-dictionary)
        header = ["Key"] + list(next(iter(new_res.values())).keys())
        writer.writerow(header)

        # Write the rows
        for main_key, sub_dict in new_res.items():
            row = [main_key] + list(sub_dict.values())
            writer.writerow(row)

    print(f"Dictionary written to {csv_file}")

