# Volatility credentials searcher plugin
#
# Copyright (C) 2016 Adrian Toma (29392@heb.be)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or (at
# your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details. 
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA 
#
"""
@author:       29392@heb.be
@license:      GNU General Public License 2.0 or later
@contact:      29392@heb.be
@organization:
"""

import time
import urlparse
import os


import volatility.utils as utils
import volatility.commands as commands
import volatility.win32.tasks as tasks
import volatility.obj as obj

def checkEnd(var_in, var_end):

    index_end = var_in.find(var_end)
    if index_end != -1:
        return var_in[:index_end]
    else:
        return var_in

def checkContains(foundCredentials, newfoundCredential):

    alreadyInList = False
    for credential in foundCredentials:
        if (credential.login == newfoundCredential.login) \
                and (credential.password == newfoundCredential.password) \
                and (credential.website == newfoundCredential.website):
            alreadyInList = True

    return alreadyInList

def showVerbose(outfd, verbose, msg):
    if verbose == 1:
        outfd.write(msg)

class Credentials(object):
    website = ""
    login = ""
    password = ""

    # The class "constructor" - It's actually an initializer
    def __init__(self):
        self.website = ""
        self.login = ""
        self.password = ""

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        os.unlink(self.website)
        os.unlink(self.login)
        os.unlink(self.password)


""" Main """
class search(commands.Command):
    """ Command parameters : search  """
    def __init__(self, config, *args, **kwargs):

        """Retrieve credentials from a memory image"""
        commands.Command.__init__(self, config, *args, **kwargs)

        # Example of argument
        config.add_option('PID', short_option='p', default=None,
                         help='Operate on these Process IDs (comma-separated) rather than all browser processes',
                         action='store', type='str')

        """argument: --browser """
        config.add_option('Browser', short_option='-browser', default=None,
                          help='Operate on these Browsers (comma-separated) (chrome, firefox, ie)',
                          action='store', type='str')

        """argument: --site """
        config.add_option('Site', short_option='-site', default=None,
                          help='Searching for this website',
                          action='store', type='str')

    def calculate(self):
        """This method performs the work"""
        # Load the address space
        address_space = utils.load_as(self._config)

        # Find browsers process
        for process in tasks.pslist(address_space):
           yield process

    def render_text(self, outfd, data):
        """Search for credentials in browsers processes and displays"""
        start_time = time.time()

        # Calculate and carry out any processing that may take time upon the image
        # List the browsers process to investigate
        browsers_process = [{'command': 'ie', 'process': 'iexplore.exe'},
                            {'command': 'firefox', 'process': 'firefox.exe'},
                            {'command': 'chrome', 'process': 'chrome.exe'}]

        # targets end patterns for each site
        targets = [{'facebook': {'website': 'www.facebook.com', 'login': '&email=', 'password': '&pass='},
                    'twitter': {'website': 'www.twitter.com', 'login': 'session%5Busername_or_email%5D=', 'password': '&session%5Bpassword%5D='},
                    'linkedin': {'website': 'www.linkedin.com', 'login': 'session_key=', 'password': '&session_password='},
                    'instagram': {'website': 'www.instagram.com', 'login': '.username=', 'password': '&password='},
                    'pinterest': {'website': 'www.pinterest.com', 'login': 'username_or_email%22%3A%22', 'password': '%22%2C%22password%22%3A%22'},
                    'gmail': {'website': 'www.gmail.com', 'login': '&Email=', 'password': '&Passwd='},
                    'youtube': {'website': 'www.youtube.com', 'login': '=&Email=', 'password': '&Passwd='},
                    'hotmail': {'website': 'www.hotmail.com', 'login': '&login=', 'password': '&passwd='},
                    'outlook': {'website': 'www.outlook.com', 'login': '&login=', 'password': '&passwd='},
                    'azure': {'website': 'account.windowsazure.com', 'login': '&login=', 'password': '&passwd='},
                    #'yahoo': {'website': 'www.yahoo.com', 'login': '"xapparentlyto":"', 'password': '&passwd='}#,
                    'amazon': {'website': 'www.amazon.com', 'login': '&email=', 'password': '&password='},
                    #'ebay': {'website': 'www.ebay.com', 'login': '&userid=&', 'password': '&runId2='},
                    # 'paypal': {'website': '', 'login': 'login_email=', 'password': ''},
                     'owa': {'website': 'owa client', 'login': '&username=', 'password': '&password='}
                    }]

        # Variables
        found = 0
        found_temp = ''
        found_credentials = []

        filter_browser = ''
        filter_website = ''

        # Adding patterns
        outfd.write('\nInitializing searching criteria\n')

        showVerbose(outfd, self._config.verbose,
                    '* Add search criteria for\n')

        criteria = []
        for websites in targets:
            for website in websites:
                if len(websites[website]['website']) > 0:
                    criteria.append(websites[website]['website'])
                    criteria.append(websites[website]['login'])
                    criteria.append(websites[website]['password'])

                    showVerbose(outfd, self._config.verbose,
                                '** {0}\n*** {1}\n*** {2}\n'.format(websites[website]['website'],
                                                                  websites[website]['login'],
                                                                  websites[website]['password']))

        # Search for processes
        outfd.write('\nSearching for browser processes...\n')

        '''Foreach process search from patterns'''
        for process in data:
            if process.UniqueProcessId:

                # Process ID
                if not self._config.PID == None and str(process.UniqueProcessId) not in list(self._config.PID.split(',')):
                    # Skip this browser pid
                    continue

                # Filtred by browser command
                if self._config.Browser != None:
                    showVerbose(outfd, self._config.verbose,
                                '* Filtred browser(s): {0}\n'.format(self._config.Browser))

                    browser_found = False
                    for browser in browsers_process:
                        if self._config.Browser == browser['command'] and str(process.ImageFileName) == browser['process']:
                            browser_found = True
                            filter_browser = self._config.Browser

                    if browser_found == False:
                        showVerbose(outfd, self._config.verbose,
                                    '* No filtred browser(s) found: {0}\n\n'.format(self._config.Browser))
                        continue


                # Filtred by site command
                if self._config.Site != None:
                    showVerbose(outfd, self._config.verbose,
                                '* Filtred website(s): {0}\n\n'.format(self._config.Site))

                    filter_website = self._config.Site

                showVerbose(outfd, self._config.verbose,
                            '** Process found : {0}\t\tpid: {1}\n'.format(process.ImageFileName, process.UniqueProcessId))


                credential = Credentials()
                found_in_process = 0

                for address in process.search_process_memory(criteria):

                    address_space = process.get_process_address_space()
                    memory_string = obj.Object('String',
                                        offset=address,
                                        vm=address_space,
                                        # encoding = 'utf_16_le',
                                        length=256)

                    for websites in targets:
                        for website in websites:

                            #if websites[website]['website'] in str(memory_string):
                            #    found_temp = str(memory_string)

                                # Clean url
                            #    found_temp = checkEnd(found_temp, '/')
                            #    found_temp = checkEnd(found_temp, '\\')
                            #    found_temp = checkEnd(found_temp, ':')
                            #    found_temp = checkEnd(found_temp, '%2F')
                            #    found_temp = checkEnd(found_temp, '"')

                            #    if credential.website != found_temp:
                            #        credential.website = found_temp
                                    #outfd.write('WEB {0}\n'.format(credential.website))


                            if websites[website]['login'] in str(memory_string):

                                credential = Credentials()

                                # LOGIN
                                currentParam = str(memory_string).find(websites[website]['login'])
                                found_temp = str(memory_string)[currentParam + len(websites[website]['login']):]

                                # Clean login, delimited from the next parameter
                                found_temp = checkEnd(found_temp, '&')

                                if credential.login != found_temp:
                                    credential.login = found_temp
                                    credential.login = urlparse.unquote(str(found_temp))
                                    outfd.write('LOGIN {0}\n'.format(credential.login))


                                # PASSWORD
                                if websites[website]['password'] in str(memory_string):
                                    currentParam = str(memory_string).find(websites[website]['password'])
                                    found_temp = str(memory_string)[(currentParam + len(websites[website]['password'])):]

                                    # Clean password, delimited from the next parameter
                                    found_temp = checkEnd(found_temp, '&')

                                    if credential.password != found_temp:
                                        credential.password = found_temp
                                        credential.password = urlparse.unquote(str(found_temp))
                                        outfd.write('PASS {0}\n'.format(credential.password))


                                # WEBSITE
                                credential.website = websites[website]['website']


                                # SAVE FOUND PARAMETERS
                                if credential.login != "" and credential.password != "":

                                    if not checkContains(found_credentials, credential):

                                        #outfd.write('\n-{0}-'.format(filter_website))
                                        #outfd.write('\n-{0}-'.format(str(website)))

                                        if filter_website == '' or filter_website == str(website):
                                            found_credentials.append(credential)

                                            showVerbose(outfd, self._config.verbose,
                                                '-- Credentials found\n\tUser:\t{0}\n\tPass:\t{1}\n\tWebsite:{2}\n'.format(
                                                credential.login,
                                                credential.password,
                                                credential.website))

                                            found += 1
                                            found_in_process += 1

                                # Clear variables
                                #found_temp = ""

                # Summary
                if found_in_process == 0:
                    showVerbose(outfd, self._config.verbose, '-- Nothing found in this process\n\n')
                else:
                    showVerbose(outfd, self._config.verbose, '--- Found in this process : {0}\n\n'.format(found))


        # Print total time of calcul
        end_time = time.time()
        outfd.write('\nTotal execution time    : {0}s\n'.format(round(end_time - start_time, 2)))
        outfd.write('Total credentials found : {0}\n\n'.format(found))

        if len(found_credentials) > 0:
            outfd.write('--- --- --- DETAILS --- --- ---'.format(found))

            for credential in found_credentials:
                outfd.write(
                    '\n\tUser:\t{0}\n\tPass:\t{1}\n\tWeb:\t{2}\n'.format(
                        credential.login,
                        credential.password,
                        credential.website))

            outfd.write('\n--- --- --- --- --- --- --- ---\n')
			