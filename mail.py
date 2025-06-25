from argparse import ArgumentParser
import json, logging, sys

from google_auth_oauthlib.flow import InstalledAppFlow

SCOPES = [
  "https://www.googleapis.com/auth/gmail.readonly",
  "https://www.googleapis.com/auth/gmail.modify"
]

def main():
  logging.basicConfig(
    datefmt = '%Y/%m/%d %I:%M:%S',
    format = '[%(asctime)s] [%(levelname)s] %(message)s',
    level = logging.INFO
  )

  parser = ArgumentParser()

  parser.add_argument("credential_path", help="Gmail API credential json path")
  args = parser.parse_args()

  if sys.gettrace() is not None:
    logging.info("Debug environment detected. Using credentials.json as path.")
    args.credential_path = "credentials.json"

  with open(args.credential_path, "r") as file:
    cred = json.load(file)

  flow = InstalledAppFlow.from_client_config(cred, SCOPES)
  creds = flow.run_local_server()

  token = creds.to_json()

  with open("token.json", "w") as file:
    json.dump(token, file)

  logging.info("Your token has been written into current folder.")

  return 0

if __name__ == "__main__": 
  sys.exit(main())