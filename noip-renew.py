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

import json
import logging
import re, os, sys, time
from argparse import ArgumentParser
from datetime import datetime, timedelta

from selenium import webdriver
from selenium.common.exceptions import TimeoutException
from selenium.webdriver.common.by import By
from selenium.webdriver.remote.webelement import WebElement
from selenium.webdriver.remote.webdriver import WebDriver
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.chrome.service import Service as ChromeService

from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from googleapiclient.discovery import build

LOGIN_URL = "https://www.noip.com/login"
HOST_URL = "https://my.noip.com/dynamic-dns"
USER_AGENT = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:64.0) Gecko/20100101 Firefox/64.0"

class MailClawer:
  SCOPES = [
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/gmail.modify"
  ]
  
  def __init__(self, authData: dict):
    creds = Credentials.from_authorized_user_info(authData, MailClawer.SCOPES)

    # Refresh credential if needed
    if creds and creds.expired and creds.refresh_token:
      creds.refresh(Request())

    self.creds = creds

    self.service = build("gmail", "v1", credentials=self.creds)
    return

  def fetch_code(self, after: datetime) -> int:
    results = self.service \
      .users() \
      .messages() \
      .list(userId='me', q=f'after:{int(after.timestamp())}') \
      .execute()
    
    messages = results.get('messages', [])

    logging.info(f"Filtered {len(messages)} emails that income after {after}")

    for msgId in map(lambda x: x["id"], messages):
      message = self.service \
        .users() \
        .messages() \
        .get(userId='me', id=msgId, format='full') \
        .execute()
      
      snippet = message.get("snippet", "")

      # Skip mail if snippet field not found
      if not snippet: continue 

      # Skip mail if it doesn't match No-IP verification mail pattern
      if not re.match(r"No-IP Verification Code For account security purposes, please enter the following verification on our website: \d{6}", snippet): continue

      # Move used verification mail to trash 
      self.service.users().messages().trash(userId='me', id=msgId).execute()
      
      return re.findall(r"\d{6}", snippet)[0] # Return matched code

class Host:
  def __init__(self, name: str, expDays: int, confirmButton: 'WebElement'):
    self.name = name
    self.expDays = expDays
    self.confirmButton = confirmButton

  @staticmethod
  def from_tr(tr: 'WebElement') -> 'Host':

    def __fetch_name(e: 'WebElement') -> str:
      return e \
        .find_element(By.XPATH, r".//a[@class='link-info cursor-pointer notranslate']") \
        .text
    
    def __fetch_exp_days(e: 'WebElement') -> int:
      matches = e.find_elements(By.XPATH, ".//a[@class='no-link-style']")
      if not matches: return 0
      return int(re.search(r"\d+", matches[0].text).group())
    
    def __fetch_button(e: 'WebElement'):
      button = e.find_elements(By.XPATH, f'.//td[6]/button[1]')

      if button and button[0].text == "Confirm":
        return button[0]
      
      return None
    
    return Host(
      name = __fetch_name(tr),
      expDays = __fetch_exp_days(tr),
      confirmButton= __fetch_button(tr)
    )
  
  @staticmethod
  def from_tr_list(tr: 'list[WebElement]') -> list['Host']:
    return [
      Host.from_tr(e) for e in tr
    ]

class LoginHandler:
  def __init__(self, driver: 'WebDriver', max2FAAttempts: int = 30):
    self.driver = driver
    self.max2FAAttempts = max2FAAttempts
    return
  
  def __await_load(self) -> None:
    WebDriverWait(self.driver, 20).until(
      lambda d: d.execute_script("return document.readyState") == "complete"
    )

  def __check_login(self):
    return len(self.driver.find_elements(By.ID, "user-email-container")) != 0
  
  def __solve_2FA(self, token: dict):
    logging.info("2FA challenge entered, fetching the 2FA code...")

    # Past 10 minutes email is acceptable
    vaild_time = datetime.now() - timedelta(minutes=10)

    service = MailClawer(token)
    
    if not service:
      logging.error(f"Gmail API service not built, script will end here.")
      return False
    
    logging.info(f"Gmail API service built, start fetching emails...")

    attempt: int = 0

    while (attempt < self.max2FAAttempts):
      logging.info(f"Attempting to get verification code from Gmail API ({attempt})")
      code = service.fetch_code(vaild_time)

      if code: break

      time.sleep(5)
      attempt += 1

    if not code:
      logging.error(f"Failed to get verification code (max attempt exceed)")
      return False

    input2fa = self.driver \
      .find_element(By.ID, "otp-input") \
      .find_elements(By.TAG_NAME, "input")
    
    for index, element in enumerate(input2fa):
      element.send_keys(str(code)[index])
    
    logging.info(f"Successfully got and entered the verification code !")

    return True

  def login_with_password(self, username: str, password: str, token: dict):
    logging.info(f"Navigating to {LOGIN_URL}")
    self.driver.get(LOGIN_URL)
    
    # Fill username and password in field, and submit the form using JS
    self.driver.execute_script(f'document.getElementById("username").value = "{username}";')
    self.driver.execute_script(f'document.getElementById("password").value = "{password}";')
    self.driver.execute_script(f'document.getElementById("clogs").submit();')
    logging.info("Username and password entered and login button clicked")

    self.__await_load()

    # If login not success after submitting the username and password, check if email 2FA is required
    if self.driver.find_elements(By.ID, "ManualSubmitMfa") and not self.__solve_2FA(token):
      logging.error("Failed to pass through the 2FA challenge")
      return False

    # Refresh page to make sure page be redirect
    self.driver.get(HOST_URL)

    if not self.__check_login():
      logging.info("Failed to login with wrong username or password suspected") 
      return False

    return True
  
class Robot:
  def __init__(self, driver: 'WebDriver'):
    self.driver = driver
    return

  def __await_navigate(self, url: str, locator: tuple[str, str]):
    self.driver.get(url)
    try: 
      WebDriverWait(self.driver, 30).until(EC.presence_of_element_located(locator))
    except TimeoutException:
      logging.error(f"Timeout for waiting element '{locator[1]}', page may not load properly")
      return False
    
    logging.info(f"Page '{url}' loaded successfully")
    return True

  def renew_hosts(self):

    if not self.__await_navigate(
      HOST_URL,
      (By.XPATH, '/html/body/div[1]/div[1]/div[2]/div/div[1]/div[1]/div[2]/div/div/div[2]/div[1]/table/tbody/tr[1]/td[1]')
    ): return False

    hosts = Host.from_tr_list(
      self.driver.find_elements(By.XPATH, r'//*[@id="host-panel"]/table/tbody/tr')
    )

    count = 0

    for host in hosts:
      if not host.confirmButton:
        logging.info(f"Host: {host.name} do not need to update")
        continue
    
      host.confirmButton.click()
      logging.info(f"Host: {host.name} has been updated.")
      time.sleep(3)

      count += 1

    logging.info(f"Confirmed hosts: {count}")

    return True

def main():
  parser = ArgumentParser()

  parser.add_argument("-p",  "--https_proxy", help="Set http proxy for selenium")
  parser.add_argument("-v",  "--verbose",     help="Increase output verbosity", action="store_true")
  parser.add_argument("-hl", "--headless",    help="Hide browser window",       action="store_true")

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

  def _fetchEnvOrRaise(env: str) -> str:
    val = os.environ.get(env)
    if val != None: return val
    parser.error(f"Environment variable {env} not found, exiting")

  username: str  = _fetchEnvOrRaise("username")
  password: str  = _fetchEnvOrRaise("password")
  token:    dict = json.loads( _fetchEnvOrRaise("token") )
  while isinstance(token, str):
    token = json.loads( token )

  # Create and initialize the web driver 
  options = webdriver.ChromeOptions()
  # options.page_load_strategy = 'eager'

  # Added for Raspbian Buster 4.0+ versions. Check https://www.raspberrypi.org/forums/viewtopic.php?t=258019 for reference.
  # options.add_argument("disable-features=VizDisplayCompositor")
  options.add_argument(f"user-agent={USER_AGENT}")
  options.add_argument("--no-sandbox") # need when run in docker
  options.add_argument("--disable-dev-shm-usage")
  options.add_argument("--disable-gpu")  # If hardware acceleration is causing issues

  if args.headless:
    options.add_argument("--headless")  # If running in a headless environment
  
  if args.https_proxy:
    options.add_argument(f"proxy-server={os.environ['https_proxy']}")

  browser = webdriver.Chrome(options=options, service=ChromeService(log_output="chromedriver.log"))
  browser.set_page_load_timeout(90) # Extended timeout for Raspberry Pi.
  browser.set_window_size(1280, 800)

  browser.delete_all_cookies()

  authApi = LoginHandler(browser)
  if not authApi.login_with_password(username, password, token):
    logging.error("Failed to log-in, script will ne here")
    return 1

  logging.info("Successfully logged into no-ip dashboard")

  refreshAPI = Robot(browser)
  if not refreshAPI.renew_hosts():
    logging.error("There is an error occur while renewing the hosts")

  logging.info("Script executed successfully")
  return 0

if __name__ == "__main__": 
  sys.exit(main())
