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

from datetime import datetime, timedelta
import json
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

from mail import Services

LOGIN_URL = "https://www.noip.com/login"
HOST_URL = "https://my.noip.com/dynamic-dns"
USER_AGENT = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:64.0) Gecko/20100101 Firefox/64.0"

class Host:
  def __init__(self, name: str, expDays: int, confirmButton: 'WebElement'):
    self.name = name
    self.expDays = expDays
    self.confirmButton = confirmButton

  @staticmethod
  def fromTrWebElement(tr: 'WebElement') -> 'Host':

    def _fetchName(e: 'WebElement') -> str:
      return e \
        .find_element(By.XPATH, r".//a[@class='link-info cursor-pointer notranslate']") \
        .text
    
    def _fetchExpDays(e: 'WebElement') -> int:
      matches = e.find_elements(By.XPATH, ".//a[@class='no-link-style']")
      if not matches: return 0
      return int(re.search(r"\d+", matches[0].text).group())
    
    def _fetchButton(e: 'WebElement'):
      button = e.find_elements(By.XPATH, f'.//td[6]/button[1]')

      if button and button[0].text == "Confirm":
        return button[0]
        
      logging.info(f"No host 'confirm' button found")
      
      return None
    
    return Host(
      name = _fetchName(tr),
      expDays = _fetchExpDays(tr),
      confirmButton= _fetchButton(tr, )
    )
  
  @staticmethod
  def fromWebElement(tr: 'list[WebElement]') -> list['Host']:
    return [
      Host.fromTrWebElement(e) for e in tr
    ]

class Robot:
  def __init__(self, username: str, password: str, token: dict, headless: bool):
    self.token = token
    self.username = username
    self.password = password

    options = webdriver.ChromeOptions()
    # options.page_load_strategy = 'eager'

    #added for Raspbian Buster 4.0+ versions. Check https://www.raspberrypi.org/forums/viewtopic.php?t=258019 for reference.
    # options.add_argument("disable-features=VizDisplayCompositor")
    options.add_argument(f"user-agent={USER_AGENT}")
    options.add_argument("--no-sandbox") # need when run in docker
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--disable-gpu")  # If hardware acceleration is causing issues

    if headless:
      options.add_argument("--headless")  # If running in a headless environment
    
    if 'https_proxy' in os.environ:
      options.add_argument(f"proxy-server={os.environ['https_proxy']}")

    self.browser = webdriver.Chrome(options=options, service=ChromeService(log_output="chromedriver.log"))
    self.browser.set_page_load_timeout(90) # Extended timeout for Raspberry Pi.
    self.browser.set_window_size(1280, 800)

    self.browser.delete_all_cookies()

  def checkLogin(self):
    element = self.browser.find_elements(By.ID, "main-menu-toggle")
    
    return len(element) != 0
  
  def fetchCode(self, maxTries: int):
    # Past 10 minutes email is acceptable
    vaild_time = datetime.now() - timedelta(minutes=10)

    service = Services(self.token)
    
    if not service:
      logging.error(f"Gmail API service not being built, script will end here.")
      return
    
    logging.info(f"Gmail API service built, start fetching emails...")

    while (maxTries > 0):
      logging.info(f"Attempting to get verification code from Gmail API ({maxTries})")
      code = service.fetchCode(vaild_time)

      time.sleep(5)

      if code: return code
      maxTries -= 1

    logging.warning(f"Failed to get verification code (timeout)")
    return None
  
  def _waitWhileLoadComplete(self) -> None:
    WebDriverWait(self.browser, 20).until(
      lambda d: d.execute_script("return document.readyState") == "complete"
    )
  
  def login(self):
    logging.info(f"Navigating to {LOGIN_URL}")
    self.browser.get(LOGIN_URL)
    
    self.browser.execute_script(f'document.getElementById("username").value = "{self.username}";')
    self.browser.execute_script(f'document.getElementById("password").value = "{self.password}";')
    self.browser.execute_script('document.getElementById("clogs").submit();')
    logging.info("Username and password entered and login button clicked")

    self._waitWhileLoadComplete()

    if self.checkLogin():
      logging.info("Login successfuly")
      return
    
    if not self.browser.find_elements(By.ID, "ManualSubmitMfa"):
      logging.info("Login failed, wrong username or password suspected")
      return 
    
    logging.info("2FA challenge entered, fetching the 2FA code...")
    code = self.fetchCode(maxTries=30)

    input2fa = self.browser.find_element(By.ID, "otp-input").find_elements(By.TAG_NAME, "input")
    
    for index, element in enumerate(input2fa):
      element.send_keys(str(code)[index])
    
    logging.info(f"Successfully got and entered the verification code !")
    
    self.browser.refresh() # Refresh page to make sure page be redirect
    try: # Wait for dashboard to load
      logging.debug(f"Current wait URL = {self.browser.current_url}")
      WebDriverWait(self.browser, 30).until(EC.presence_of_element_located((By.ID, "app")))
    except TimeoutException:
      return logging.error("Cannot load dashboard page, login may not success")

    logging.info("Login successfuly")
    return True

  def updateHosts(self):

    self._navigateAndWaitFor(HOST_URL, (By.XPATH, '/html/body/div[1]/div[1]/div[2]/div/div[1]/div[1]/div[2]/div/div/div[2]/div[1]/table/tbody/tr[1]/td[1]'))

    hosts = Host.fromWebElement(
      self.browser.find_elements(By.XPATH, r'//*[@id="host-panel"]/table/tbody/tr')
    )

    count = 0

    for host in hosts:
      if self.updateHost(host.confirmButton, host.name):
        count += 1
      
    self.browser.save_screenshot("results.png")
    logging.info(f"Confirmed hosts: {count}")

    return True

  def _navigateAndWaitFor(self, url: str, locator: tuple[str, str]):
    self.browser.get(url)
    try: 
      WebDriverWait(self.browser, 30).until(EC.presence_of_element_located(locator))
    except TimeoutException:
      logging.error(f"Timeout for waiting element '{locator[1]}', page may not load properly\nScreenshot: {self.browser.get_screenshot_as_base64()}")
      return
    logging.info(f"Page '{url}' loaded successfully")

    self.browser.save_screenshot("NEW2.png")

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

  def fetchHosts(self):
    # Navigate to hosts list URL
    self._navigateAndWaitFor(HOST_URL, (By.CLASS_NAME,'table-striped-row'))

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

  logging.basicConfig(
    datefmt = '%Y/%m/%d %I:%M:%S',
    format = '[%(asctime)s] [%(levelname)s] %(message)s',
    level = logging.INFO
  )

  if sys.gettrace() is not None:
    logging.info("Debug environment detected. Using environment variable to execute the script.")
    args.verbose = True
    args.headless = False
    args.environment_variable = True
  
  username: str
  password: str
  token: dict

  def _fetchEnvOrRaise(env: str) -> str:
    val = os.environ.get(env)
    if val != None:
      return val
    parser.error(f"Environment variable {env} not found, exiting")
    
  if args.environment_variable:
    username = _fetchEnvOrRaise("username")
    password = _fetchEnvOrRaise("password")
    token = json.loads( _fetchEnvOrRaise("token") )
    while isinstance(token, str):
      token = json.loads( token )

  else:
    if not args.username:
      parser.error("Please provide username with -u")

    if not args.password:
      parser.error("Please provide password with -p")

    if not args.token_path:
      parser.error("Please provide token path with -t")
    
    username = args.username
    password = args.password
    with open(args.token_path, "r") as f:
      token = json.load(f)

  robot = Robot(username, password, token, args.headless)

  return robot.renew()

if __name__ == "__main__": 
  sys.exit(main())
