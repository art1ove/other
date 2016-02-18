#!/usr/bin/python

import rpm
import json
import urllib2
import re
import sys
from optparse import OptionParser
import os

class bcolors:
    RED = '\033[91m'
    YELLOW = '\033[93m'
    VIOLET = '\033[95m'
    GREEN = '\033[92m'
    WHITE = '\033[1m'
    BLUE = '\033[94m'
    UNDERLINE = '\033[4m'  # Underline
    ENDC = '\033[0m'       # End of the coloring line

parser= OptionParser(usage="Usage: %prog [options]",
        description='Searching for vulnerable system packages. Good to use with |sort')

parser.add_option('-s',
                  '--server',
                  action='store',
                  type='string',
                  dest='server',
                  help='JSON server IP/DNS address')

parser.add_option('-A',
                  '--all',
                  action='store_true',
                  dest='all',
                  help='Print all vulnerability packages')

parser.add_option('-c',
                  '--critical',
                  action='store_true',
                  dest='critical',
#                  default='false',
                  help='Print packages with Critical severity')# \
#                  (Default - printing all packages)')

parser.add_option('-m',
                  '--moderate',
                  action='store_true',
                  dest='moderate',
                  help='Print packages with Moderate severity')

parser.add_option('-i',
                  '--important',
                  action='store_true',
                  dest='important',
                  help='Print packages with Important severity')

parser.add_option('-l',
                  '--low',
                  action='store_true',
                  dest='low',
                  help='Print packages with Low severity')

parser.add_option('-L',
                  '--links',
                  action='store_true',
                  dest='links',
                  help='Display links to RHSA issues')

parser.add_option('-q',
                  '--quiet',
                  action='store_true',
                  dest='quiet',
                  help='Dont print status messages to stdout')

(options,args)=parser.parse_args()

if len(sys.argv[1:]) == 0:
    #print parser.print_help()
    print parser.error("No options given")
    sys.exit(1)
else:
    pass

if options.server:
    if re.search('http', options.server):
        if options.quiet:
            url=options.server
        else:
            url=options.server
            print bcolors.BLUE + "===>" + bcolors.ENDC, \
                 bcolors.WHITE + "Looking for JSON in" + bcolors.ENDC, \
                 bcolors.GREEN + url + bcolors.ENDC + \
                 bcolors.WHITE + "..." + bcolors.ENDC
    else:
        if options.quiet:
           url="http://" + options.server + "/"
        else:
            url="http://" + options.server + "/"
            print bcolors.BLUE + "===>" + bcolors.ENDC, \
                 bcolors.WHITE + "Looking for JSON in" + bcolors.ENDC, \
                 bcolors.GREEN + url + bcolors.ENDC + \
                 bcolors.WHITE + "..." + bcolors.ENDC
else:
    #print parser.print_help()
    #print parser.error("server IP/DNS address is required")
    #sys.exit(1);
    if options.quiet:
        url="http://172.16.98.39/"
    else:
        url="http://172.16.98.39/"
        print bcolors.BLUE + "===>" + bcolors.ENDC, \
             bcolors.WHITE + "JSON server address is not set. Using default" + bcolors.ENDC, \
             bcolors.GREEN + url + bcolors.ENDC

data = urllib2.urlopen(url)
parsed = json.load(data)
ts = rpm.TransactionSet()
d={}

with open('/etc/centos-release', 'r') as f:
    centos_ver = "CentOS " + re.search('\d', f.read()).group()

for package in parsed[centos_ver]:
    mi = ts.dbMatch('name', package['pkg'])
    if mi:
        for h in mi:
            pass
        if rpm.labelCompare(('1', package['version'], package['release']), \
        ('1', h['version'], h['release'])) == 1:
            pkg_dict = package['pkg'] + package['version'] + package ['release'], "-", package['issue']
            severity = package['severity']
            if severity in d:
                d[severity].append(pkg_dict)
            else:
                d[severity] = [pkg_dict]


def print_issues(a):
    if options.all:
        print d
    elif options.critical:
        for package in d:
            print d['Critical']
    elif options.moderate:
        print d['Moderate']

print_issues(d)



#def stdout(severity):
#    issue_year = re.search('-\d*', package['issue']).group()
#    issue_num = re.search(':\d*', package['issue']).group()
#    issue_num = re.search('\d+', issue_num).group()
#    if options.all:
#        if options.links:
#            print "[", bcolors.RED + package['severity'] + bcolors.ENDC, "]", \
#                  "-", package['issue'], "-", \
#                  bcolors.WHITE + "%s-%s-%s" % (h['name'], h['version'], h['release']) + bcolors.ENDC, \
#                  bcolors.BLUE + " # https://rhn.redhat.com/errata/RHSA" + issue_year \
#                  + "-" + issue_num +".html" + bcolors.ENDC
#        else:
#             print "[", bcolors.RED + package['severity'] + bcolors.ENDC, "]", \
#                   "-", package['issue'], "-", \
#                   bcolors.WHITE + "%s-%s-%s" % (h['name'], h['version'], h['release']) + bcolors.ENDC
#    elif package['severity'] == 'Critical':
#        if options.critical:
#            if options.links:
#                print "[", bcolors.RED + package['severity'] + bcolors.ENDC, "]", \
#                      "-", package['issue'], "-", \
#                      bcolors.WHITE + "%s-%s-%s" % (h['name'], h['version'], h['release']) + bcolors.ENDC, \
#                      bcolors.BLUE + " # https://rhn.redhat.com/errata/RHSA" + issue_year + \
#                      "-" + issue_num +".html" + bcolors.ENDC
#        else:
#            print "[", bcolors.RED + package['severity'] + bcolors.ENDC, "]", \
#                  "-", package['issue'], "-", \
#                  bcolors.WHITE + "%s-%s-%s" % (h['name'], h['version'], h['release']) + bcolors.ENDC
#            else:
#                pass
#     elif package['severity'] == 'Moderate':
#         if options.moderate:
#             if options.links:
#                 print "[", bcolors.VIOLET+ package['severity'] + bcolors.ENDC, "]", \
#                       "-", package['issue'], "-", \
#                       bcolors.WHITE + "%s-%s-%s" % (h['name'], h['version'], h['release']) + bcolors.ENDC, \
#                       bcolors.BLUE + " # https://rhn.redhat.com/errata/RHSA" + issue_year + \
#                       "-" + issue_num +".html" + bcolors.ENDC
#         else:
#             print "[", bcolors.VIOLET + package['severity'] + bcolors.ENDC, "]", \
#                   "-", package['issue'], "-", \
#                   bcolors.WHITE + "%s-%s-%s" % (h['name'], h['version'], h['release']) + bcolors.ENDC
#             else:
#                 pass
#     elif package['severity'] == 'Important':
#         if options.important:
#             if options.links:
#                 print "[", bcolors.YELLOW + package['severity'] + bcolors.ENDC, "]", \
#                       "-", package['issue'], "-", \
#                       bcolors.WHITE + "%s-%s-%s" % (h['name'], h['version'], h['release']) + bcolors.ENDC, \
#                       bcolors.BLUE + " # https://rhn.redhat.com/errata/RHSA" + issue_year \
#                       + "-" + issue_num +".html" + bcolors.ENDC
#          else:
#              print "[", bcolors.YELLOW + package['severity'] + bcolors.ENDC, "]", \
#                    "-", package['issue'], "-", \
#                    bcolors.WHITE + "%s-%s-%s" % (h['name'], h['version'], h['release']) + bcolors.ENDC
#              else:
#                  pass
#     elif package['severity'] == 'Low':
#         if options.low:
#             if options.links:
#                 print "[", bcolors.GREEN + package['severity'] + bcolors.ENDC, "]", \
#                       "-", package['issue'], "-", \
#                       bcolors.WHITE + "%s-%s-%s" % (h['name'], h['version'], h['release']) + bcolors.ENDC, \
#                       bcolors.BLUE + " # https://rhn.redhat.com/errata/RHSA" + issue_year \
#                       + "-" + issue_num +".html" + bcolors.ENDC
#         else:
#             print "[", bcolors.GREEN + package['severity'] + bcolors.ENDC, "]", \
#                   "-", package['issue'], "-", \
#                   bcolors.WHITE + "%s-%s-%s" % (h['name'], h['version'], h['release']) + bcolors.ENDC
#             else:
#                 pass


#print json.dumps(d, indent=2)
