#!/bin/python3

import argparse
import json
from datetime import datetime as dt
from os.path import exists


def should_ignore(
        vulnerability: dict, ignored_files: list, ignored_identifiers: list
) -> bool:
    """
    Check if the vulnerability should be ignored based on the ignored args.

    Args:
        vulnerability (dict): vulnerability found from the reports.
        ignored_files (list): list of files to be ignored.
        ignored_identifiers (list): list of identifiers names to be ignored.

    Returns:
        bool: True if the vulnerability should be ignored.
    """
    per_type = any([
        True if identifier['name'] in ignored_identifiers else False
        for identifier in vulnerability['identifiers']
    ])
    per_path = any([
        True if vulnerability['location']['file'].startswith(path) else False
        for path in ignored_files
    ])
    return any([per_type, per_path])


def filter_vulnerabilities(
        vulnerabilities: list, ignored_files: list, ignored_identifiers: list
) -> tuple:
    """
    Filter the vulnerabilities based on the ignored args.

    Args:
        vulnerabilities (list): list of found vulnerabilities.
        ignored_files (list): list of files to be ignored.
        ignored_identifiers (list): list of identifiers names to be ignored.

    Returns:
        tuple:
            [0]: filtered list of vulnerabilities.
            [1]: list of rejected vulnerabilities.
    """
    output = []
    ignored = []
    for each in vulnerabilities:
        if should_ignore(each, ignored_files, ignored_identifiers):
            ignored.append(each)
        else:
            output.append(each)
    return output, ignored


def classify_per_severity(vulnerabilities: list) -> dict:
    """
    Classify the vulnerabilities based on severity.

    Args:
        vulnerabilities (list): list of vulnerabilities from the reports.

    Returns:
        dict: classified dict with keys for each risk level
            (critical, high, medium, low and info)
    """
    classified = {
        'critical': [],
        'high': [],
        'medium': [],
        'low': [],
        'info': [],
    }
    for each in vulnerabilities:
        classified[each['severity'].lower()].append(each)
    return classified


def classify_per_confidence(vulnerabilities: list) -> dict:
    """
    Classify the vulnerabilities based on confidence level.

    Args:
        vulnerabilities (list): list of vulnerabilities from the reports.

    Returns:
        dict: classified dict with keys for each confidence level
            (unknown, high, medium and low)
    """
    classified = {
        'unknown': [],
        'high': [],
        'medium': [],
        'low': [],
    }
    for each in vulnerabilities:
        if 'confidence' in each:
            classified[each['confidence'].lower()].append(each)
        else:
            classified['unknown'].append(each)
    return classified


def read_files(files: list, path: str) -> tuple:
    """
    Read vulnerabilities data from report files.

    Args:
        files (list): list of file names to be processed.
        path (str): path to the files to be processes.

    Returns:
        tuple:
            [0] list of vulnerabilities,
            [1] earliest start time from the reports,
            [2] latest end time from the reports.
    """
    start = dt.now()
    end = dt.strptime('2000', '%Y')

    print('Vulnerabilities per SAST tool:')
    vulnerabilities_raw = []
    for filename in files:
        file_path = '/'.join([path, filename])
        if exists(file_path):
            with open(file_path) as file:
                data = json.load(file)
                start = min(
                    dt.fromisoformat(data['scan']['start_time']), start
                )
                end = max(dt.fromisoformat(data['scan']['end_time']), end)
                print(
                    f'{filename.split(".")[0].capitalize()}\t\t'
                    f'{len(data["vulnerabilities"])}'
                )
                vulnerabilities_raw += data['vulnerabilities']
    print('-' * 50)
    return vulnerabilities_raw, start, end


def clear_vulnerabilities_data(vulnerabilities: list) -> list:
    """
    Parser to clean and set the pattern for the vulnerabilities.

    Args:
        vulnerabilities (list): list of vulnerabilities to be processed.

    Returns:
        list: list of processed vulnerabilities.
    """
    output = []
    for each in vulnerabilities:
        try:
            identifiers = {i['type']: i['name'] for i in each['identifiers']}
            urls = {i['type']: i.get('url') for i in each['identifiers']}
            output.append({
                'category': each.get('category'),
                'description': each.get('description'),
                'message': each.get('message'),
                'severity': each.get('severity'),
                'confidence': each.get('confidence', 'unknown'),
                'scanner': each.get('scanner', {}).get('id'),
                'location': (
                    f'{each["location"]["file"]}:{each["location"]["end_line"]}'
                ),
                'identifiers': identifiers,
                'urls': urls,
            })
        except KeyError as err:
            print(each)
            print(err)
    return output


def write_processed_file(vulnerabilities: list, filepath: str) -> None:
    """
    Write the final processed report to a file.

    Args:
        vulnerabilities (list): list of vulnerabilities to be saved.
        filepath (str): path/filename to save the file.
    """
    with open(filepath, 'w') as file:
        json.dump(vulnerabilities, file, sort_keys=True, indent=2)


def merge_similar(vulnerabilities: list) -> list:
    """
    Merge similar vulnerabilities based on identifiers.

    Each tool can generate their identifiers in different ways, which will
    cause duplicated data at the end report.

    TODO: Find a simple way of eliminating duplicated vulnerabilities found
    with multiple tools.

    Args:
        vulnerabilities (list): list of vulnerabilities.

    Returns:
        list: list of vulnerabilities with merged locations.
    """
    output = []
    identifiers = []
    for vulnerability in vulnerabilities:
        if vulnerability['identifiers'] in identifiers:
            pos = identifiers.index(vulnerability['identifiers'])
            output[pos]['location'].append(vulnerability['location'])
        else:
            identifiers.append(vulnerability['identifiers'])
            vulnerability['location'] = [vulnerability['location']]
            output.append(vulnerability)
    return output


def security_report(
        input_files: list,
        input_path: str,
        output_file: str,
        ignored_files: list,
        ignored_identifiers: list,
        reasons: list,
        resumed_json: str,
        header: str,
        subtitle: str
):
    """
    Process multiple SAST reports cleaning ignored files and ignored
    identifiers, generating a final processed report and a summary.

    Args:
        input_files (list): list of input files to be processed.
        input_path (str): path of input files to be processed.
        output_file (str): output file where the processed data will be saved.
        ignored_files (list): list of path/files to be ignored (partial name
            check).
        ignored_identifiers (list): list of identifiers names to be ignored.
        reasons (list): list of reasons for the filters (only shown on final
            CLI summary).
        resumed_json (str): path to the resumed json file.
    """
    print('-' * 50)
    vulnerabilities_raw, start, end = read_files(input_files, input_path)
    filtered, ignored = filter_vulnerabilities(
        vulnerabilities_raw, ignored_files, ignored_identifiers
    )
    vulnerabilities = clear_vulnerabilities_data(filtered)
    merged = merge_similar(vulnerabilities)

    classified_severity = classify_per_severity(vulnerabilities)
    classified_confidence = classify_per_confidence(vulnerabilities)
    merged_severity = classify_per_severity(merged)
    merged_confidence = classify_per_confidence(merged)

    write_processed_file(merged, output_file)

    print('Scanning time (GMT):')
    print(f'Started at\t{start}')
    print(f'Ended at\t{end}')
    print(f'Duration\t{end - start}')
    print('-' * 50)
    print(f'Total Found\t{len(vulnerabilities_raw)}')
    print(f'Ignored\t\t{len(ignored)}')
    print(f'Filtered\t{len(vulnerabilities)}')
    print(f'Reasons:')
    for reason in reasons:
        print(f'- {reason}')
    print('-' * 50)
    print('Severity\tFiles\tVulnerabilities')
    print(
        f'Critical\t{len(classified_severity["critical"])}'
        f'\t{len(merged_severity["critical"])}'
    )
    print(
        f'High\t\t{len(classified_severity["high"])}'
        f'\t{len(merged_severity["high"])}'
    )
    print(
        f'Medium\t\t{len(classified_severity["medium"])}'
        f'\t{len(merged_severity["medium"])}'
    )
    print(
        f'Low\t\t{len(classified_severity["low"])}'
        f'\t{len(merged_severity["low"])}'
    )
    print(
        f'Info\t\t{len(classified_severity["info"])}'
        f'\t{len(merged_severity["info"])}'
    )
    print('-' * 50)
    print('Confidence\tFiles\tVulnerabilities')
    print(
        f'High\t\t{len(classified_confidence["high"])}'
        f'\t{len(merged_confidence["high"])}'
    )
    print(
        f'Medium\t\t{len(classified_confidence["medium"])}'
        f'\t{len(merged_confidence["medium"])}'
    )
    print(
        f'Low\t\t{len(classified_confidence["low"])}'
        f'\t{len(merged_confidence["low"])}'
    )
    print(
        f'Unknown\t\t{len(classified_confidence["unknown"])}'
        f'\t{len(merged_confidence["unknown"])}'
    )
    print('-' * 50)

    def generate_dict(classified, merged):
        value = ''
        for key in classified:
            value += (
                f'\t\t- {key}:\n'
                f'\t\t\tarquivos: {len(classified[key])}\n'
                f'\t\t\tvulnerabilidades: {len(merged[key])}\n'
            )
        return value

    output = {
        'header': header,
        'subtitle': subtitle,
        'message': (
            f'Metricas:\n'
            f'\t\tInicio: {start}\n'
            f'\t\tFim: {end}\n'
            f'\t\tDuração: {end - start}\n'
            'Vulnerabilidades:\n'
            f'\t\ttotal: {len(vulnerabilities_raw)}\n'
            f'\t\tignored: {len(ignored)}\n'
            f'\t\tfiltered: {len(vulnerabilities)}\n'
            f'\t\treasons: {[reason for reason in reasons]}\n'
            f'Severidade:\n{generate_dict(classified_severity, merged_severity)}'
            f'Confiabilidade:\n{generate_dict(classified_confidence, merged_confidence)}'
        ),
    }
    if resumed_json:
        with open(resumed_json, 'w') as file:
            file.write(json.dumps(output))


def cli():
    parser = argparse.ArgumentParser(description='Process SAST reports.')
    parser.add_argument(
        '--input-files', '-i',
        required=True,
        nargs='+',
        type=str,
        help='list of input files to be processed.',
    )
    parser.add_argument(
        '--input-path', '-p',
        required=False,
        type=str,
        help='path of input files to be processed.',
        default='./',
    )
    parser.add_argument(
        '--output-file', '-o',
        required=False,
        type=str,
        help='output file where the processed data will be saved.',
        default='./output.json',
    )
    parser.add_argument(
        '--ignored-files', '-if',
        required=False,
        nargs='+',
        type=str,
        help='list of path/files to be ignored (partial name check).',
        default=[],
    )
    parser.add_argument(
        '--ignored-identifiers', '-ii',
        required=False,
        nargs='+',
        type=str,
        help='list of identifiers names to be ignored.',
        default=[],
    )
    parser.add_argument(
        '--reasons', '-r',
        required=False,
        nargs='+',
        type=str,
        help=(
            'list of reasons for the filters '
            '(only shown on final CLI summary).'
        ),
        default=[],
    )
    parser.add_argument(
        '--resumed-json', '-rj',
        required=False,
        type=str,
        help='path to resumed json.',
        default='',
    )
    parser.add_argument(
        '--header', '-head',
        required=False,
        type=str,
        help='header for resume json',
        default='Header',
    )
    parser.add_argument(
        '--subtitle', '-sub',
        required=False,
        type=str,
        help='subtitle for resume json',
        default='Subtitle',
    )
    args = parser.parse_args()
    security_report(
        args.input_files,
        args.input_path,
        args.output_file,
        args.ignored_files,
        args.ignored_identifiers,
        args.reasons,
        args.resumed_json,
        args.header,
        args.subtitle
    )


if __name__ == '__main__':
    cli()
