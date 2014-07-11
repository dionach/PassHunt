#! /usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright (c) 2014, Dionach Ltd. All rights reserved. See LICENSE file.
#
# PassHunt: search directories and sub directories for files containing passwords
# By BB

import os, sys, zipfile, re, datetime, cStringIO, argparse, time, hashlib, unicodedata, platform, string, xml.sax.saxutils
import colorama
import progressbar
import filehunt

app_version = '0.9.1'


###################################################################################################################################
#   ____ _                         
#  / ___| | __ _ ___ ___  ___  ___ 
# | |   | |/ _` / __/ __|/ _ \/ __|
# | |___| | (_| \__ \__ \  __/\__ \
#  \____|_|\__,_|___/___/\___||___/
#                                  
###################################################################################################################################


class PWDFile(filehunt.AFile):
    """ PassFile: class for a file that can check itself for passwords"""

    PREFIX_COUNT = 40
    SUFFIX_COUNT = 180

    def __init__(self, filename, file_dir):
        
        filehunt.AFile.__init__(self, filename, file_dir)
        #self.type = None # DOC, ZIP, MAIL, SPECIAL, OTHER  


    def check_text_regexs(self, text, regexs, sub_path):
        """Uses regular expressions to check for passwords in text"""

        hanging_start = -1
        last_end = -1
        for pass_type, regex in regexs.items():
            for pwd_match in regex.finditer(text):
                if last_end == -1 or last_end + PWDFile.SUFFIX_COUNT < pwd_match.start() - PWDFile.PREFIX_COUNT:
                    self.add_password_subtext(hanging_start, text, pwd_match, pass_type, sub_path)
                    hanging_start = -1
                else:
                    hanging_start = pwd_match.start()
                last_end = pwd_match.end()
        if hanging_start != -1:
            self.add_password_subtext(hanging_start, text, pwd_match, pass_type, sub_path)

    def add_password_subtext(self, hanging_start, text, pwd_match, pass_type, sub_path):

        if hanging_start == -1:
            subtext_start = pwd_match.start()
        else:
            subtext_start = hanging_start
        subtext = text[subtext_start - PWDFile.PREFIX_COUNT : pwd_match.end() + PWDFile.SUFFIX_COUNT]
        subtext = filter(lambda x: x in string.printable, subtext)
        subtext = subtext.replace('\n',' ').replace('\r',' ').replace('\t',' ').replace('  ',' ').replace('  ',' ')[:150]
        self.matches.append(PWD(self.path, sub_path, pass_type, subtext))


class PWD:
    """PWD: A class for recording passwords, their type and where they were found"""

    def __init__(self, path, sub_path, pass_type, subtext):
        
        self.path, self.sub_path, self.pass_type, self.pwd = path, sub_path, pass_type, subtext


    def __repr__(self):

        return '%s: %s' % (self.sub_path, self.pwd)


    def get_masked_pwd(self):

        return '*%s*' % self.pwd[1:-1]
        


###################################################################################################################################
#  __  __           _       _        _____                 _   _                 
# |  \/  | ___   __| |_   _| | ___  |  ___|   _ _ __   ___| |_(_) ___  _ __  ___ 
# | |\/| |/ _ \ / _` | | | | |/ _ \ | |_ | | | | '_ \ / __| __| |/ _ \| '_ \/ __|
# | |  | | (_) | (_| | |_| | |  __/ |  _|| |_| | | | | (__| |_| | (_) | | | \__ \
# |_|  |_|\___/ \__,_|\__,_|_|\___| |_|   \__,_|_| |_|\___|\__|_|\___/|_| |_|___/
#
###################################################################################################################################                                                                                


def output_report(search_dir, excluded_directories_string, all_files, total_docs, pwds_found, output_file):

    css = """<style type="text/css">
                    table {border-collapse:collapse;}
                    table, td, th {border:1px solid darkgray;}
                    td {padding-left:5px; padding-right:5px;}
                    .t1 {font-weight: bold;}
                    .s1 {background-color: lightblue;}
                    .s2 {background-color: yellow;}
                    .s3 {background-color: orangered;}
                    .ts {font-weight: normal; font-size: smaller}
                    </style>"""

    report = u'<html><head><title>Pass Hunt Report</title>%s</head><body>\n' % (css)
    report += u'<h1>Pass Hunt Report - %s</h1>\n' % (time.strftime("%H:%M:%S %d/%m/%Y"))
    report += u'<p>Searched %s\nExcluded %s</p>\n' % (search_dir, excluded_directories_string)
    report += u'<p>Command: %s</p>\n' % (' '.join(sys.argv))
    report += u'<p>Uname: %s</p>\n' % (' | '.join(platform.uname()))
    report += u'<p>Searched %s files. Found %s possible passwords.</p>\n' % (total_docs, pwds_found)
    
    report += u'<table>'
    for afile in sorted([afile for afile in all_files if afile.matches]):
        report += '<tr><td class="t1 s1"><a href="file://%s">%s</a> (%s %s)</td></tr>\n' % (afile.path, afile.path, afile.size_friendly(), afile.modified.strftime('%d/%m/%Y'))
        pwd_list = u'' + u'<br />'.join([u'<b>{0}</b> {1}'.format(pwd.sub_path, esc_xml(pwd.pwd)) for pwd in afile.matches])
        report += '<tr><td>%s</td></tr>\n' % pwd_list
    
    if len([afile for afile in all_files if afile.type == 'OTHER']) <> 0:
        report += u'<tr><td class="t1 s1">Interesting Files to check separately:</td></tr>\n'
    for afile in sorted([afile for afile in all_files if afile.type == 'OTHER']):
        report += u'<tr><td><a href="file://%s">%s</a> (%s %s)</td></tr>\n' % (afile.path, afile.path, afile.size_friendly(), afile.modified.strftime('%d/%m/%Y'))

    report += u'</table></body></html>'

    print colorama.Fore.WHITE + 'Report written to %s' % filehunt.unicode2ascii(output_file)
    filehunt.write_unicode_file(output_file, report)


def esc_xml(s):
    
    if s:
        return xml.sax.saxutils.escape(s)
    else:
        return ''


###################################################################################################################################
#  __  __       _       
# |  \/  | __ _(_)_ __  
# | |\/| |/ _` | | '_ \ 
# | |  | | (_| | | | | |
# |_|  |_|\__,_|_|_| |_|
#
###################################################################################################################################


if __name__ == "__main__":

    colorama.init()

    # defaults
    search_dir = u'C:\\'
    output_file = u'passhunt_%s.html' % time.strftime("%Y-%m-%d-%H%M%S")
    regex_string = u'password'
    excluded_directories_string = u'C:\\Windows,C:\\Program Files,C:\\Program Files (x86)'
    text_extensions_string =  u'.doc,.xls,.xml,.txt,.csv,.config,.ini,.vbs,.vbscript,.bat,.pl,.asp,.sh,.php,.inc,.conf,.inf,.reg'
    zip_extensions_string = u'.docx,.xlsx,.zip'
    special_extensions_string = u'.msg'
    mail_extensions_string = u'.pst'
    other_extensions_string = u'.ost,.accdb,.mdb,.kdb,.asc,.cer,.crt,.pem,.der' # checks for existence of files that can't be checked automatically
    
    # Command Line Arguments
    arg_parser = argparse.ArgumentParser(prog='passhunt', description='PassHunt v%s: search directories and sub directories for documents containing passwords.' % (app_version), formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    arg_parser.add_argument('-s', dest='search', default=search_dir, help='base directory to search in')
    arg_parser.add_argument('-r', dest='regex', default=regex_string, help='regular expression to search for')
    arg_parser.add_argument('-x', dest='exclude', default=excluded_directories_string, help='directories to exclude from the search')
    arg_parser.add_argument('-t', dest='textfiles', default=text_extensions_string, help='text file extensions to search')
    arg_parser.add_argument('-z', dest='zipfiles', default=zip_extensions_string, help='zip file extensions to search')
    arg_parser.add_argument('-e', dest='specialfiles', default=special_extensions_string, help='special file extensions to search')
    arg_parser.add_argument('-m', dest='mailfiles', default=mail_extensions_string, help='email file extensions to search')
    arg_parser.add_argument('-l', dest='otherfiles', default=other_extensions_string, help='other file extensions to list')
    arg_parser.add_argument('-o', dest='outfile', default=output_file, help='HTML output file name for report')

    args = arg_parser.parse_args()    
    
    search_dir = unicode(args.search)
    output_file = unicode(args.outfile)
    regex_string = unicode(args.regex)
    excluded_directories_string = unicode(args.exclude)
    text_extensions_string = unicode(args.textfiles)    
    zip_extensions_string = unicode(args.zipfiles)
    special_extensions_string = unicode(args.specialfiles)
    mail_extensions_string = unicode(args.mailfiles)
    other_extensions_string = unicode(args.otherfiles)

    excluded_directories = [exc_dir.lower() for exc_dir in excluded_directories_string.split(',')]

    search_extensions = {}
    search_extensions['TEXT'] = text_extensions_string.split(',')
    search_extensions['ZIP'] = zip_extensions_string.split(',')
    search_extensions['SPECIAL'] = special_extensions_string.split(',')
    search_extensions['MAIL'] = mail_extensions_string.split(',')
    search_extensions['OTHER'] = other_extensions_string.split(',')
    # TO DO: how about network drives, other databases?

    pass_regexs = {'password': re.compile(regex_string, re.IGNORECASE)}

    # find all files to check
    all_files = filehunt.find_all_files_in_directory(PWDFile, search_dir, excluded_directories, search_extensions)
    # TODO: search for filenames containing 'password', and encrypted zip/documents
    
    # check each file
    total_docs, doc_pans_found = filehunt.find_all_regexs_in_files([afile for afile in all_files if not afile.errors and afile.type in ('TEXT','ZIP','SPECIAL')], pass_regexs, search_extensions, 'Pwd')
    # check each pst message and attachment
    total_psts, pst_pans_found = filehunt.find_all_regexs_in_psts([afile for afile in all_files if not afile.errors and afile.type == 'MAIL'], pass_regexs, search_extensions, 'Pwd')

    pans_found = doc_pans_found + pst_pans_found

    # report findings
    output_report(search_dir, excluded_directories_string, all_files, total_docs, pans_found, output_file)