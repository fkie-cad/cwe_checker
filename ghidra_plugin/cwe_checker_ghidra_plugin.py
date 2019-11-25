# Import the results of the cwe_checker as bookmarks and comments into Ghidra.
#
# Usage:
# - Run the cwe_checker on a binary and save its output as a json file.
# - Copy this file into the Ghidra scripts folder
# - Open the binary in Ghidra and run this file as a script. Select the generated json file when prompted.

import json


def bookmark_cwe(ghidra_address, text):
    previous_bookmarks = getBookmarks(ghidra_address)
    for bookmark in previous_bookmarks:
        if '[cwe_checker]' == bookmark.getCategory():
            if text not in bookmark.getComment():
                createBookmark(ghidra_address, '[cwe_checker]', bookmark.getComment() + '\n' + text)
            return
    createBookmark(ghidra_address, '[cwe_checker]', text)
    return


def comment_cwe_eol(ghidra_address, text):
    old_comment = getEOLComment(ghidra_address)
    if old_comment is None:
        setEOLComment(ghidra_address, text)
    elif text not in old_comment:
        setEOLComment(ghidra_address, old_comment + '\n' + text)


def comment_cwe_pre(ghidra_address, text):
    old_comment = getPREComment(ghidra_address)
    if old_comment is None:
        setPREComment(ghidra_address, text)
    elif text not in old_comment:
        setPREComment(ghidra_address, old_comment + '\n' + text)


def get_cwe_checker_output():
    ghidra_file = askFile('Select json output file of the cwe_checker', 'Open')
    with open(ghidra_file.getAbsolutePath()) as json_file:
        return json.load(json_file)


def compute_ghidra_address(address_string):
    fixed_address_string = address_string.replace(':32u', '').replace(':64u', '')
    address = int(fixed_address_string, 16)
    return currentProgram.minAddress.add(address)


def main():
    """
    Annotate cwe_checker results (including check_path paths) in Ghidra as end-of-line
    comments and bookmarks to the corresponding addresses.
    """
    cwe_checker_output = get_cwe_checker_output()
    warnings = cwe_checker_output['warnings']
    for warning in warnings:
        if len(warning['addresses']) == 0:
            cwe_text =  '[' + warning['name'] + '] ' + warning['description']
            ghidra_address = currentProgram.minAddress.add(0)
            bookmark_cwe(ghidra_address, cwe_text)
            comment_cwe_pre(ghidra_address, cwe_text)
        else:
            for address_string in warning['addresses']:
                ghidra_address = compute_ghidra_address(address_string)
                bookmark_cwe(ghidra_address, warning['description'])
                comment_cwe_eol(ghidra_address, warning['description'])
    if 'check_path' in cwe_checker_output:
        for check_path in cwe_checker_output['check_path']:
            ghidra_address = compute_ghidra_address(check_path['source_addr'])
            check_path_string = 'Path to CWE at ' + check_path['destination_addr'] + ': ' + check_path['path_str']
            bookmark_cwe(ghidra_address, check_path_string)
            comment_cwe_eol(ghidra_address, check_path_string)


main()
