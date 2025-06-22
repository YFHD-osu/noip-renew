from argparse import ArgumentParser
from datetime import datetime
import json, logging, sys, re, os.path

from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from googleapiclient.discovery import build, Resource
from google_auth_oauthlib.flow import InstalledAppFlow

# If modifying these scopes, delete the file token.json.


class Services:
  SCOPES = [
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/gmail.modify"
  ]
  
  def __init__(self, authData: dict):
    creds = Credentials.from_authorized_user_info(authData, Services.SCOPES)

    # Refresh credential if needed
    if creds and creds.expired and creds.refresh_token:
      creds.refresh(Request())

    self.creds = creds

    self.service = build("gmail", "v1", credentials=self.creds)
    return

  def fetchCode(self, after: datetime) -> int:
    messages_resource: Resource = self.service.users().messages()

    vaild_messages = messages_resource.list(
      userId="me",
      labelIds=["CATEGORY_UPDATES"],
      q=f"after:{int(after.timestamp())}"
    ).execute()

    logging.info(f"Filtering {vaild_messages.get('resultSizeEstimate', 0)} possible email...")

    for msgId in map(lambda x: x["id"], vaild_messages.get("messages", [])):
      msg = vaild_messages.get(userId="me", id=msgId).execute()
      subject = list(filter(lambda e: e["name"] == "Subject", msg["payload"]["headers"]))

      # Skip mail if subject field not found
      if not len(subject): continue 
      
      # Skip mail if it doesn't match No-IP verification mail pattern
      if not re.match(r"No-IP Verification Code: \d{6}", subject[0]["value"]): continue

      # Move used verification mail to trash 
      vaild_messages.trash(userId="me", id=msgId).execute()
      
      return re.findall(r"\d{6}", subject[0]["value"])[0] # Return matched code

  @staticmethod
  def authoirzeFlow(credential: dict) -> dict:
    flow = InstalledAppFlow.from_client_config(credential, Services.SCOPES)
    creds = flow.run_local_server()

    return creds.to_json()


# def buildService(token: str) -> Resource:
#   """Shows basic usage of the Gmail API. Lists the user's Gmail labels."""

#   creds = None
#   # The file token.json stores the user's access and refresh tokens, and is
#   # created automatically when the authorization flow completes for the first
#   # time.

#   if not token: 
#     if not os.environ.get("token"):
#       return logging.error("Environment variable: \"token\" not found")
    
#     logging.info("Environment variable: \"token\" found, using it to login...")
#     data = json.loads(os.environ["token"])
#     creds = Credentials.from_authorized_user_info(data, SCOPES)
  
#   elif os.path.exists(token):
#     logging.info(f"File: \"{token}\" found, using it to login...")
#     creds = Credentials.from_authorized_user_file(token, SCOPES)

  
#   # Call the Gmail API
  

def main():
  logging.basicConfig(
    datefmt = '%Y/%m/%d %I:%M:%S',
    format = '[%(asctime)s] [%(levelname)s] %(message)s',
    level = logging.INFO
  )

  parser = ArgumentParser()

  parser.add_argument("-cred", "--credential", help="Gmail API credential json path")
  args = parser.parse_args()

  if sys.gettrace() is not None:
    logging.info("Debug environment detected. Using credentials.json as path")
    args.credential = "credentials.json"

  with open(args.credential, "r") as file:
    cred = json.load(file)

  token = Services.authoirzeFlow(cred)

  with open("token.json", "w") as file:
    json.dump(token, file)

  logging.info("Your token has been written into current folder.")

  return 0

  

if __name__ == "__main__": 
  sys.exit(main())