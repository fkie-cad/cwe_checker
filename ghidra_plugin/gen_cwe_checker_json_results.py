# Generate results of the cwe_checker and import them as bookmarks and comments into Ghidra.
#
# Usage:
# - Copy this file into the Ghidra scripts folder
# - Open the binary in Ghidra and run this file as a script. If a json hasn't been generated for the hash of the executable, it will be generated at runtime.

import json
import subprocess
import os


def bookmark_cwe(ghidra_address, text):
    previous_bookmarks = getBookmarks(ghidra_address)
    for bookmark in previous_bookmarks:
        if '[cwe_checker]' == bookmark.getCategory():
            if text not in bookmark.getComment():
                return createBookmark(ghidra_address, '[cwe_checker]', bookmark.getComment() + '\n' + text)
    return createBookmark(ghidra_address, '[cwe_checker]', text)


def comment_cwe_eol(ghidra_address, text):
    old_comment = getEOLComment(ghidra_address)
    if old_comment is None:
        return setEOLComment(ghidra_address, text)
    elif text not in old_comment:
        return setEOLComment(ghidra_address, old_comment + '\n' + text)


def comment_cwe_pre(ghidra_address, text):
    old_comment = getPreComment(ghidra_address)
    if old_comment is None:
        setPreComment(ghidra_address, text)
    elif text not in old_comment:
        setPreComment(ghidra_address, old_comment + '\n' + text)


def get_cwe_checker_output(json_file):
    with open(json_file) as f:
        return json.load(f)

def prepare_json_cache_folder(cache_folder_name='__cwe_checker_json_cache'):
    proj_dir = getState().getProject().getProjectData().getProjectLocator().projectDir
    cache_dir_path = os.path.join(proj_dir.toString(), cache_folder_name)
    if not os.path.exists(cache_dir_path):
        os.mkdir(cache_dir_path)
    assert os.path.isdir(cache_dir_path), cache_dir_path
    return cache_dir_path

def make_cwe_check_json(path2binary, outfile):
    assert os.path.exists(path2binary), path2binary
    return subprocess.check_output(["cwe_checker", path2binary, "--quiet", "--json", "--out", "{}".format(str(outfile)),])

def parse_warnings_and_annotate(warnings):
    prog = getCurrentProgram()
    for warning in warnings:
        if len(warning['addresses']) == 0:
            cwe_text =  '[' + warning['name'] + '] ' + warning['description']
            ghidra_address = prog.getMinAddress().add(0)
            result_bm = bookmark_cwe(ghidra_address, cwe_text)
            result_c = comment_cwe_pre(ghidra_address, cwe_text)
        else:
            address_string = warning['addresses'][0]
            ghidra_address = prog.getAddressFactory().getAddress(address_string)
            result_bm = bookmark_cwe(ghidra_address, warning['description'])
            result_c = comment_cwe_eol(ghidra_address, warning['description'])
        if (not result_bm) or (not result_c):
            print("DBG: Failed to add warning to,",
                  '' if result_bm else 'bookmark',
                  '' if result_c else 'comment',
                  ". Warning is {}".format(repr(warning)))
    else:
        print("CWE Checker: Done annotating! {} warnings.".format(str(len(warnings))))


def main():
    """
    Annotate cwe_checker results in Ghidra as end-of-line
    comments and bookmarks to the corresponding addresses.
    """
    prog = getCurrentProgram()
    json_file = "{}.json".format(prog.getExecutableSHA256())
    json_file = os.path.join(prepare_json_cache_folder(), json_file)
    if not os.path.exists(json_file):
        make_cwe_check_json(prog.getExecutablePath(), json_file)
    warnings = get_cwe_checker_output(json_file)
    parse_warnings_and_annotate(warnings)

main()
