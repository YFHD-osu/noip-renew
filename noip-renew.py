#!/usr/bin/env python3
# Copyright 2017 loblab
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import logging
import re, os, sys, time
from argparse import ArgumentParser

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.common.exceptions import TimeoutException
from selenium.webdriver.remote.webelement import WebElement

from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.chrome.service import Service as ChromeService

from mail import buildService, fetchCode

LOGIN_URL = "https://www.noip.com/login"
HOST_URL = "https://my.noip.com/dynamic-dns"
USER_AGENT = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:64.0) Gecko/20100101 Firefox/64.0"

class Robot:
  def __init__(self, username: str, password: str, token: str, headless: bool, verbose: bool):
    self.token = token
    self.username = username
    self.password = password

    options = webdriver.ChromeOptions()
    options.page_load_strategy = 'eager'

    #added for Raspbian Buster 4.0+ versions. Check https://www.raspberrypi.org/forums/viewtopic.php?t=258019 for reference.
    # options.add_argument("disable-features=VizDisplayCompositor")
    options.add_argument("window-size=1200x800")
    options.add_argument(f"user-agent={USER_AGENT}")
    options.add_argument("--no-sandbox") # need when run in docker
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--disable-gpu")  # If hardware acceleration is causing issues

    if headless:
      options.add_argument("--headless")  # If running in a headless environment
    
    if verbose:
      options.add_argument("--verbose")

    if 'https_proxy' in os.environ:
      options.add_argument(f"proxy-server={os.environ['https_proxy']}")

    self.browser = webdriver.Chrome(options=options, service=ChromeService(log_output="chromedriver.log"))
    self.browser.set_page_load_timeout(90) # Extended timeout for Raspberry Pi.

  def login(self):
    logging.info(f"Opening {LOGIN_URL}...")
    self.browser.get(LOGIN_URL)

    logging.info("Logging in...")
    ele_usr = self.browser.find_element(By.NAME ,"username")
    ele_pwd = self.browser.find_element(By.NAME, "password")
    ele_usr.send_keys(self.username)
    ele_pwd.send_keys(self.password)

    self.browser.find_element(By.ID, "clogs-captcha-button").click()

    if "noip.com/2fa/verify" in self.browser.current_url:
      attempts = 0

      # Past 10 minutes email is acceptable
      now = int(time.time() - 600) 
      service = buildService(self.token)
      
      if not service:
        return logging.error(f"Gmail API service not being built, script will end here.")
      
      logging.info(f"Gmail API service built, start fetching emails...")

      while True:
        attempts += 1
        if attempts > 30:
          logging.warning(f"Failed to get verification code (timeout)")
          return None
        
        logging.info(f"Attempting to get verification code from Gmail API ({attempts})")
        code = fetchCode(service, now)

        if code: break # Exit check loop if code is vaild
        time.sleep(5) # Prevent too many requests 
        
        # # Click "resend email" button if it's enabled
        # resendBtn = self.browser.find_element(By.ID, "resend")
        # if (resendBtn.is_enabled()) : resendBtn.click()

      logging.info(f"Successfully got the verification code !")
      input2fa = self.browser.find_element(By.ID, "otp-input").find_elements(By.TAG_NAME, "input")
      
      for index, element in enumerate(input2fa):
        element.send_keys(str(code)[index])

      logging.info(f"Current login URL = {self.browser.current_url}")
      self.browser.find_element(By.NAME, "submit").click()
    
    logging.debug(f"Current wait URL = {self.browser.current_url}")
    self.browser.refresh() # Refresh page to make sure page be redirect
    try: # Wait for dashboard to load
      logging.debug(f"Current wait URL = {self.browser.current_url}")
      WebDriverWait(self.browser, 30).until(EC.presence_of_element_located((By.ID, "app")))
    except TimeoutException:
      return logging.error("Cannot load dashboard page, login may not success")

    logging.info("Login successfuly")
    return True

  def updateHosts(self):
    count = 0
    next_renewal = []

    self.__openHostsPage()
    hosts = self.fetchHosts()
    for index, host in enumerate(hosts):
      hostLink = self.fetchHostLink(host) # This is for if we wanted to modify our Host IP.
      hostBtn = self.fetchHostButton(host, index+1) # This is the button to confirm our free host
      expDays = self.fetchHostExpirationDays(host)
      hostName = hostLink.text
      next_renewal.append(expDays)
      logging.info(f"{hostName} expires in {str(expDays)} days")

      if self.updateHost(hostBtn, hostName):
        count += 1
      
    self.browser.save_screenshot("results.png")
    logging.info(f"Confirmed hosts: {count}")

    return True

  def __openHostsPage(self):
    logging.info(f"Opening {HOST_URL}...")
    self.browser.get(HOST_URL)
    try: 
      WebDriverWait(self.browser, 30).until(EC.presence_of_element_located((By.CLASS_NAME,'table-striped-row')))
    except TimeoutException:
      logging.error("Timeout to wait for element \"table-striped-row\", host page may not load properly")
      return
    logging.info("Host page loaded successfully")

    # print("I wanna close")
    # time.sleep(1000)

  def updateHost(self, hostBtn: WebElement, hostName: str) -> bool:
    if hostBtn == None:
      logging.info(f"Host: {hostName} do not need to update")
      return False
    
    hostBtn.click()
    logging.info(f"Host: {hostName} has been updated.")
    time.sleep(3)

    intervention = False
    try:
      if self.browser.find_elements(By.XPATH, "//h2[@class='big']")[0].text == "Upgrade Now":
        intervention = True
    except:
      pass

    if intervention:
      raise Exception("Manual intervention required. Upgrade text detected.")

    self.browser.save_screenshot(f"{hostName}_success.png")

  @staticmethod
  def fetchHostExpirationDays(host: 'WebElement'):
    matches = host.find_elements(By.XPATH, ".//a[@class='no-link-style']")
    if not len(matches): return 0
    return int(re.search(r"\d+", matches[0].text).group())

  @staticmethod
  def fetchHostLink(host: 'WebElement'):
    return host.find_element(By.XPATH, r".//a[@class='link-info cursor-pointer notranslate']")

  @staticmethod
  def fetchHostButton(host: 'WebElement', index: 'int'):
    button = host.find_elements(By.XPATH, f"""//*[@id="host-panel"]/table/tbody/tr[{index}]/td[6]/button[1]""")
    if not len(button): return logging.info("Host \"confirm\" button not found")

    if button[0].text != "Confirm": return None
    return button[0]

  def fetchHosts(self):
    host_tds = self.browser.find_elements(By.XPATH, "//td[@data-title=\"Host\"]")
    if len(host_tds) == 0:
      raise Exception("No hosts or host table rows not found")
    return host_tds

  def renew(self):
    self.login()
    self.updateHosts()
    self.browser.quit()

def main():
  parser = ArgumentParser()

  parser.add_argument("-u", "--username", help="Your No-IP login account username")
  parser.add_argument("-p", "--password", help="Your No-IP login account password")
  parser.add_argument("-t", "--token-path", help="Path to your Gmail API token json file", default="token.json")
  parser.add_argument("-e", "--environment-variable", help="If this flag be added, username; password; token arguments will not required", action='store_true')
  parser.add_argument("-v", "--verbose", help="Increase output verbosity", action="store_true")
  parser.add_argument("-hl", "--headless", help="Hide browser window", action="store_true")

  args = parser.parse_args()

  if not ( (args.username and args.password) or (args.environment_variable) ):
    if not (args.username or args.password or args.environment_variable):
      parser.error("Please provide your login information with [\"-u\" and \"-p\"] or [\"-e\"] ")

    if args.password ^ args.username: 
      parser.error("Please provide both username and password")
    
  token = args.token_path if not args.environment_variable else None
  username = args.username if (args.username) else os.environ.get("username")
  password = args.password if (args.password) else os.environ.get("password")

  logging.basicConfig(
    datefmt = '%Y/%m/%d %I:%M:%S',
    format = '[%(asctime)s] [%(levelname)s] %(message)s',
    level = logging.DEBUG if args.verbose else logging.INFO
  )

  if not (username and password):
    parser.error("Environment variables for username and password not found")

  return Robot(username, password, token, args.headless, args.verbose).renew()

if __name__ == "__main__": sys.exit(main())
