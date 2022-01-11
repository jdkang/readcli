#!/bin/env python3

import pathlib
from google.oauth2 import credentials
import googleapiclient.discovery as gdisc
from loguru import logger
from google_auth_oauthlib.flow import InstalledAppFlow
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
import pprint

def get_google_creds(
    client_scopes,
    client: dict = {},
    client_secrets_filename: str = "client_secrets.json",
    force_reauth: bool = False
):
    # client secrets and token files stored on disk relative to script
    script_directory_path = pathlib.Path(__file__).parent
    client_secrets_file_path = pathlib.Path.joinpath(
        script_directory_path, client_secrets_filename
    )
    token_file_path = pathlib.Path.joinpath(script_directory_path, "token.json")
    if force_reauth:
        token_file_path.unlink(missing_ok=True)

    # OAuth2 Flow: https://github.com/googleapis/google-api-python-client/blob/main/docs/oauth.md
    creds = None
    if token_file_path.exists():
        logger.debug("importing creds from disk")
        creds = Credentials.from_authorized_user_file(str(token_file_path))
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            try:
                creds.refresh(Request())
            except:
                logger.exception("google token refresh ex:")
                
        else:
            if len(client) > 0:
                # by client formatted obj
                logger.debug("starting google auth flow with client config")
                flow = InstalledAppFlow.from_client_config(
                    client,
                    scopes=client_scopes
                )
            else:
                # by client secrest file
                logger.debug("starting google auth flow with client secrets file")
                if not client_secrets_file_path.exists():
                    raise Exception("could not find client_secrets.json")

                flow = InstalledAppFlow.from_client_secrets_file(
                    client_secrets_file_path.as_posix(),
                    scopes=client_scopes
                )
            creds = flow.run_local_server(port=0)
        # save token
        token_file_path.write_text(creds.to_json())
    return creds

class gtasks:
    def __init__(
        self,
        client: dict = {},
        client_secrets_filename: str = "client_secrets.json"
    ):
        gcredkwargs = {
            'client_scopes': ["https://www.googleapis.com/auth/tasks"],
            'client_secrets_filename': client_secrets_filename
        }
        if len(client) > 0:
            gcredkwargs['client'] = client
        creds = get_google_creds(**gcredkwargs)
        self._gapi = gdisc.build("tasks", "v1", credentials=creds)

    def get_list(self, task_list_name: str):
        return gtask_list(task_list_name=task_list_name, gapi=self._gapi)


class gtask_list:
    def __init__(self, task_list_name: str, gapi: gdisc.Resource):
        task_list_result = gapi.tasklists().list(maxResults=10).execute()
        task_lists = task_list_result.get("items", [])
        task_list = [
            x for x in task_lists if str.lower(x["title"]) == str.lower(task_list_name)
        ]

        if len(task_list) == 0:
            raise Exception(f"Could not find list {task_list_name}")
        elif len(task_list) == 1:
            self._gapi = gapi
            self._task_list = task_list[0]
            self.refresh_tasks()

    def refresh_tasks(self, showCompleted=False):
        task_list_id = self._task_list["id"]
        task_result = (
            self._gapi.tasks()
            .list(tasklist=task_list_id, showCompleted=showCompleted)
            .execute()
        )
        tasks = task_result.get("items", [])
        self.tasks = sorted(tasks, key=lambda i: i["position"])

    def patch_task(self, task: dict):
        if task["kind"] != "tasks#task":
            raise ValueError("kind is not tasks#task")
        task_list_id = self._task_list["id"]
        self._gapi.tasks().patch(
            tasklist=task_list_id, task=task["id"], body=task
        ).execute()

    def mark_task_complete(self, task: dict):
        if task["kind"] != "tasks#task":
            raise ValueError("kind is not tasks#task")
        updated_task = task.copy()
        updated_task["status"] = "completed"
        self.patch_task(task=updated_task)


def main():
    gt = gtasks()
    scrape_list = gt.get_list("scrape")
    print(len(scrape_list.tasks))
    pprint.pprint(scrape_list.tasks)

    print("")
    print("---------------------------------")
    print("")
    if len(scrape_list.tasks) > 0:
        t = scrape_list.tasks[0]
        print(f"marking {t['title']} complete")
        x = scrape_list.mark_task_complete(t)

    print("")
    print("---------------------------------")
    print("")
    scrape_list.refresh_tasks()
    print(len(scrape_list.tasks))
    pprint.pprint(scrape_list.tasks)


if __name__ == "__main__":
    main()
