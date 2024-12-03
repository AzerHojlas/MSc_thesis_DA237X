import maltoolbox
from maltoolbox.language import classes_factory
from maltoolbox.language import specification
from maltoolbox.attackgraph import attackgraph
from maltoolbox import model
from maltoolbox.ingestors import neo4j
import pydot
import warnings
import logging
# import os

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
warnings.filterwarnings("ignore", category=UserWarning, message="Schema id not specified")
warnings.filterwarnings("ignore", category=UserWarning, message="Schema version not specified")
logging.disable(logging.CRITICAL)


def parse_dot_file(dot_file_path):
    graph = pydot.graph_from_dot_data(
        open(dot_file_path, "r", encoding="utf-16").read()
    )[0]
    nodes = [node.get_name() for node in graph.get_nodes()][1:]
    return [node.split(".")[-1][:-1] for node in nodes], (
        [(edge.get_source().split(".")[-1][:-1], edge.get_destination().split(".")[-1][:-1]) for edge in graph.get_edges()]
        if graph
        else print("Failed to parse DOT file.")
    )

nodes, edges = parse_dot_file(r"C:\Users\AzerHojlas\Desktop\examensarbete\Målmiljö\plan.dot")

lang_file = "org.mal-lang.redigoLang-0.0.1.mar"
lang_spec = specification.load_language_specification_from_mar(lang_file)
specification.save_language_specification_to_json(lang_spec, 'lang_spec.json')
lang_classes_factory = classes_factory.LanguageClassesFactory(lang_spec)
lang_classes_factory.create_classes()
toolbox = model.Model('Simple Example Model', lang_spec, lang_classes_factory)

list_of_assets_and_steps = dir(lang_classes_factory.ns)

for asset in nodes:
    asset = asset.split("_")
    asset_category = asset[0]
    asset_type = asset[1]
    asset_name = asset[2]
    if asset_type in list_of_assets_and_steps:
        toolbox.add_asset(getattr(lang_classes_factory.ns, asset_type)(name = asset_name))
    else:
        logger.error(f"Asset {asset_name} of type {asset_type} is not in the list of assets and steps")

for edge in edges:
    assoc1 = edge[0].split("_")
    assoc2 = edge[1].split("_")
    for asset in toolbox.assets:
        if assoc1[2] == asset.name[:-2]:
            assoc1[2] = asset.name
        elif assoc2[2] == asset.name[:-2]:
            assoc2[2] = asset.name
    assets_exist = True if (assoc1[1] in list_of_assets_and_steps) and (assoc2[1] in list_of_assets_and_steps) else False
    associaion_exists = False
    if assets_exist:
        for association_dict in specification.get_associations_for_class(lang_spec, assoc1[1]):
            direct_association_exists_order_1 = (assoc1[1] in association_dict['leftAsset'] and assoc2[1] in association_dict['rightAsset'])
            direct_association_exists_order_2 = (assoc2[1] in association_dict['leftAsset'] and assoc1[1] in association_dict['rightAsset'])
            direct_association_exists = True if direct_association_exists_order_1 or direct_association_exists_order_2 else False
            if direct_association_exists:
                try:
                    if direct_association_exists_order_1:
                        left_asset = [toolbox.get_asset_by_name(assoc1[2])]
                        right_asset = [toolbox.get_asset_by_name(assoc2[2])]
                    elif direct_association_exists_order_2:
                        left_asset = [toolbox.get_asset_by_name(assoc2[2])]
                        right_asset = [toolbox.get_asset_by_name(assoc1[2])]
                    else:
                        left_asset = None
                        right_asset = None

                    association = getattr(lang_classes_factory.ns, association_dict['name'])()
                    exec(f'association.{association_dict['leftField']} = left_asset')
                    exec(f'association.{association_dict['rightField']} = right_asset')
                    toolbox.add_association(association)
                    assert left_asset is not None
                    assert right_asset is not None
                except Exception as e:
                    logger.error('whoopsie')
                    logger.error(e)
            extended_association_exists_order_1 = (specification.extends_asset(lang_spec, assoc1[1], association_dict['leftAsset']) and specification.extends_asset(lang_spec, assoc2[1], association_dict['rightAsset'])) 
            extended_association_exists_order_2 = (specification.extends_asset(lang_spec, assoc2[1], association_dict['leftAsset']) and specification.extends_asset(lang_spec, assoc1[1], association_dict['rightAsset']))
            extended_association_exists = True if extended_association_exists_order_1 or extended_association_exists_order_2 else False
            if extended_association_exists:
                try:    
                    if extended_association_exists_order_1:
                        extended_left_asset = [toolbox.get_asset_by_name(assoc1[2])] 
                        extended_right_asset = [toolbox.get_asset_by_name(assoc2[2])]
                    elif extended_association_exists_order_2:
                        extended_left_asset = [toolbox.get_asset_by_name(assoc2[2])]
                        extended_right_asset = [toolbox.get_asset_by_name(assoc1[2])]
                    else:
                        extended_left_asset = None
                        extended_right_asset = None
                    extended_association = getattr(lang_classes_factory.ns, association_dict['name'])()
                    exec(f'extended_association.{association_dict['leftField']} = extended_left_asset')
                    exec(f'extended_association.{association_dict['rightField']} = extended_right_asset')
                    toolbox.add_association(extended_association)
                    assert extended_left_asset is not None
                    assert extended_right_asset is not None
                except Exception as e:
                    logger.error(f'whoopsie extended, {association_dict['leftField']}, {extended_association}, {dir(extended_left_asset[0])}, {dir(extended_right_asset[0])}')
                    logger.error(e)

vuln = lang_classes_factory.ns.CWE_862_Missing_Authorization(name = 'CWE_862')
toolbox.add_asset(vuln)
vuln_assoc =\
    lang_classes_factory.ns.ApplicationVulnerability_SoftwareVulnerability_Application(
    application = [toolbox.get_asset_by_name('database:0')],
    vulnerabilities = [vuln]
    )
toolbox.add_association(vuln_assoc)

attacker1 = model.AttackerAttachment(name='Azerinho', entry_points=[(toolbox.get_asset_by_name('database:0'), ['useVulnerability']), (toolbox.get_asset_by_name('ApacheWebServer:2'), ['fullAccess']), (toolbox.get_asset_by_name("virtualPrivateCloud:7"), ['fullAccess'])])
toolbox.add_attacker(attacker1)
toolbox.save_to_file('simple_example_model.json')
graph = attackgraph.AttackGraph(lang_spec=lang_spec, model=toolbox)
graph.attach_attackers(toolbox)
graph.save_to_file('simple_example_attack_graph.json')

maltoolbox.neo4j_configs['uri'] = '' # add uri
maltoolbox.neo4j_configs['username'] = 'neo4j'
maltoolbox.neo4j_configs['password'] = '' # add password
maltoolbox.neo4j_configs['dbname'] = 'neo4j'

if maltoolbox.neo4j_configs['uri'] != "":
    neo4j.ingest_model(toolbox,
        maltoolbox.neo4j_configs['uri'],
        maltoolbox.neo4j_configs['username'],
        maltoolbox.neo4j_configs['password'],
        maltoolbox.neo4j_configs['dbname'],
        delete=True)
    neo4j.ingest_attack_graph(graph,
        maltoolbox.neo4j_configs['uri'],
        maltoolbox.neo4j_configs['username'],
        maltoolbox.neo4j_configs['password'],
        maltoolbox.neo4j_configs['dbname'],
        delete=False)
