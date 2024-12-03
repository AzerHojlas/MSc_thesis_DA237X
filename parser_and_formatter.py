from maltoolbox.language import classes_factory
from maltoolbox.language import specification
import pydot
import warnings
import logging
import subprocess
import shutil
import os
import xml.etree.ElementTree as ET

logger = logging.getLogger(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
warnings.filterwarnings(
    "ignore", category=UserWarning, message="Schema id not specified"
)
warnings.filterwarnings(
    "ignore", category=UserWarning, message="Schema version not specified"
)
logging.disable(logging.CRITICAL)

detected_vulns = []


def extend_MAL_assets(file_path, name, extends_asset, removes):
    content_to_insert = (
        f"\n\tasset {name} extends {extends_asset}\n\t{{\n\t\t| {removes}\n\t}}\n"
    )
    with open(file_path, "r") as file:
        file_content = file.read()
    last_brace_index = file_content.rfind("}")
    part_before_last_brace = file_content[:last_brace_index]
    part_from_last_brace = file_content[last_brace_index:]
    modified_content = part_before_last_brace + content_to_insert + part_from_last_brace
    with open(file_path, "w") as file:
        file.write(modified_content)


def extend_MAL_vulnerability(file_path, name, exploit_name, target, consequence, user_info, target_info):
    content_to_insert = f'''
\tasset CWE_{name} extends SoftwareVulnerability
\tuser info: "{target_info} weakness. {user_info}"
\t{{
\t\t|\t{exploit_name}
\t\t\tdeveloper info: "XML file CWE mapping"
\t\t\t-> {target}.{consequence}
\t}}
'''
    with open(file_path, "r", encoding="utf-8") as file:  # Ensuring UTF-8 encoding
        file_content = file.read()
    last_brace_index = file_content.rfind("}")
    part_before_last_brace = file_content[:last_brace_index]
    part_from_last_brace = file_content[last_brace_index:]
    modified_content = part_before_last_brace + content_to_insert + part_from_last_brace
    with open(file_path, "w", encoding="utf-8") as file:  # Writing back with UTF-8 encoding
        file.write(modified_content)


def parse_dot_file(dot_file_path):
    graph = pydot.graph_from_dot_data(
        open(dot_file_path, "r", encoding="utf-16").read()
    )[0]
    nodes = [node.get_name() for node in graph.get_nodes()][1:]
    return [node.split(".")[-1][:-1] for node in nodes], (
        [(edge.get_source(), edge.get_destination()) for edge in graph.get_edges()]
        if graph
        else print("Failed to parse DOT file.")
    )


def compile_and_move_mal(file_path, destination_folder):
    if not os.path.exists(destination_folder):
        raise FileNotFoundError(
            f"Destination folder '{destination_folder}' does not exist."
        )
    original_dir = os.getcwd()
    os.chdir(os.path.dirname(file_path) or ".")
    try:
        result = subprocess.run(
            ["malc", os.path.basename(file_path)], capture_output=True, text=True
        )
        print(result.stdout)
        if result.stderr:
            print("Error:", result.stderr)
        else:
            generated_file = "org.mal-lang.redigoLang-0.0.1.mar"
            shutil.move(
                generated_file, os.path.join(destination_folder, generated_file)
            )
            print(f"Moved {generated_file} to {destination_folder}")
    finally:
        os.chdir(original_dir)


mal_file = (
    r"C:\Users\AzerHojlas\Desktop\examensarbete\RedigoLang\src\main\mal\redigoLang.mal"
)
# parse_and_append_associations(mal_file)

nodes, edges = parse_dot_file(
    r"C:\Users\AzerHojlas\Desktop\examensarbete\Målmiljö\plan.dot"
)
lang_file = "org.mal-lang.coreLang-1.0.0.mar"
lang_spec = specification.load_language_specification_from_mar(lang_file)
specification.save_language_specification_to_json(lang_spec, "lang_spec.json")
lang_classes_factory = classes_factory.LanguageClassesFactory(lang_spec)
lang_classes_factory.create_classes()
list_of_assets_and_steps = dir(lang_classes_factory.ns)

for node in nodes:
    info = node.split("_")
    if info[1] not in list_of_assets_and_steps:
        extend_MAL_assets(mal_file, info[1], info[4], info[6])


tree = ET.parse(
    r"C:\Users\AzerHojlas\Desktop\examensarbete\CWE lists\Mappings\Top 25\1425.xml"
)
for node in nodes:
    info = node.split("_")
    for elem in tree.iterfind(".//{http://cwe.mitre.org/cwe-7}Weakness"):
        for target_type in elem.find(
            "{http://cwe.mitre.org/cwe-7}Applicable_Platforms"
        ):
            target = list(target_type.attrib.values())[0]
            if info[1] in target and len(info) > 6 and info[1] not in detected_vulns:
                detected_vulns.append(info[1])
                extend_MAL_vulnerability(
                    file_path=mal_file, 
                    name = f"{elem.attrib['ID']}_{elem.attrib['Name'].replace(" ", "_")}", 
                    exploit_name=info[8],  
                    target=info[9], 
                    consequence=info[10], 
                    user_info = elem.find("{http://cwe.mitre.org/cwe-7}Description").text, 
                    target_info = target
                )


input_mal_path = (
    r"C:\Users\AzerHojlas\Desktop\examensarbete\RedigoLang\src\main\mal\main.mal"
)
output_dir = (
    r"C:\Users\AzerHojlas\Desktop\examensarbete\test_environment\CoreLang_File\Test"
)
compile_and_move_mal(input_mal_path, output_dir)

