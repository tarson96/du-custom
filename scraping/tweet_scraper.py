# import sys
# sys.path.append("/mnt/d/Google Drive/Temp/Desktop/Freelance/Clients/Potiential Clients/Varun S/code/du-custom")
import orjson
from twitter import search, scraper
from twitter.search import Search, get_headers
from twitter.util import find_key
from twitter.constants import *
import requests
import random
import time
from datetime import datetime, timedelta
from httpx import AsyncClient
from pathlib import Path
import bittensor as bt
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
import json
import traceback
from twitter.login import execute_login_flow, Client, flow_start, flow_instrumentation, flow_username, flow_password, flow_duplication_check, init_guest_token, confirm_email, solve_confirmation_challenge
# from common.data import DataLabel
# import asyncio
# import nest_asyncio
# asyncio.set_event_loop_policy(asyncio.DefaultEventLoopPolicy())
# nest_asyncio.apply()

# bt.logging.basicConfig(format='%(asctime)s - %(levelname)s - %(message)s',
#                     datefmt='%d-%b-%y %H:%M:%S',
#                     level=bt.logging.DEBUG)

def execute_login_flow_v2(client: Client, **kwargs) -> Client | None:
    client = init_guest_token(client)
    for fn in [flow_start, flow_instrumentation, flow_username, flow_password, flow_duplication_check]:
        client = fn(client)
    # solve email challenge
    if client.cookies.get('confirm_email') == 'true':
        client = confirm_email(client)
    # solve confirmation challenge (Proton Mail only)
    if client.cookies.get('confirmation_code') == 'true':
        if not kwargs.get('proton'):
            print(f'[{RED}warning{RESET}] Please check your email for a confirmation code'
                  f' and log in again using the web app. If you wish to automatically solve'
                  f' email confirmation challenges, add a Proton Mail account in your account settings')
            client.cookies.set('confirmation_code','true')
            # return
        # client = solve_confirmation_challenge(client, **kwargs)
    return client

def login_v2(email: str, username: str, password: str, **kwargs) -> Client:
    client = Client(
        cookies={
            "email": email,
            "username": username,
            "password": password,
            "guest_token": None,
            "flow_token": None,
        },
        headers={
            'authorization': 'Bearer AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA',
            'content-type': 'application/json',
            'user-agent': random.choice(USER_AGENTS),
            'x-twitter-active-user': 'yes',
            'x-twitter-client-language': 'en',
        },
        follow_redirects=True
    )
    client = execute_login_flow_v2(client, **kwargs)

    
    # if not client or client.cookies.get('flow_errors') == 'true':
    #     raise Exception(f'flow_token')

    
    return client

class CredentialManager_V2:
    def verify_all_credentials(self, username=None):
        def process_credential(credential):
            # bt.logging.info(f"Verifying credential: {credential['username']}")
            status = self._check_account_status(credential)
            if status == 'active':
                self.release_credential(credential)
            if status == 'skip':
                self.release_credential(credential)
            else:
                self._update_credential_database(credential, status)
            bt.logging.info(f"credential {credential['username']} is {status}")
            return credential['username'], status
        bt.logging.info("Verifying all credentials.")
        url = "http://tstempmail1.pythonanywhere.com/api/credentials/"
        response = requests.get(url)
        if response.status_code == 200:
            credentials = response.json()
            if username:
                credentials = [credential for credential in credentials if credential['username'] == username]
        else:
            bt.logging.warning(f"Failed to fetch credentials: {response.text}")
            credentials=[]
        with ThreadPoolExecutor(max_workers=10) as executor:
            future_to_credential = {executor.submit(process_credential, credential): credential for credential in credentials}
            for future in as_completed(future_to_credential):
                credential = future_to_credential[future]
                try:
                    username, status = future.result()
                except Exception as exc:
                    bt.logging.error(f"{credential['username']} generated an exception: {exc}")
        
        # bt.logging.info("Verifying identity verification credentials.")
        # url = "http://tstempmail1.pythonanywhere.com/api/credentials/"
        # response = requests.get(url)
        # if response.status_code == 200:
        #     credentials = response.json()
        #     if username:
        #         credentials = [credential for credential in credentials if credential['username'] == username and credential['status']=='email_verification']
        # else:
        #     bt.logging.error(f"Failed to fetch credentials: {response.text}")
        #     credentials=[]
        
        # with ThreadPoolExecutor(max_workers=10) as executor:
        #     future_to_credential = {executor.submit(process_credential, credential): credential for credential in credentials}
        #     for future in as_completed(future_to_credential):
        #         credential = future_to_credential[future]
        #         try:
        #             username, status = future.result()
        #         except Exception as exc:
        #             bt.logging.error(f"{credential['username']} generated an exception: {exc}")



    def request_credential(self, _type = 'debug'):
        try:
            response = requests.get(f"http://tstempmail1.pythonanywhere.com/api/lock_credential/?ctype={_type}")
            if response.status_code == 200:
                self.credential = response.json()
                status = self._check_account_status(self.credential)
                if status == 'active':
                    bt.logging.info(f"Fetched Credential: {self.credential['username']}")
                    return self.credential
                elif status == 'skip':
                    # bt.logging.info(f"There is some issue while fetching credential {self.credential['username']}. Skipping and fetching different one .. ")
                    return None
                else:
                    self.release_credential(self.credential)
                    self._update_credential_database(self.credential, status)
                    return None
            else:
                if 'No credentials available' in response.text:
                    requests.get('http://tstempmail1.pythonanywhere.com/api/activate_all/')
                    self.verify_all_credentials()
                    
                bt.logging.warning(f"Error while fetching credentials: {response.text}")
                return  None
        except requests.RequestException as e:
            bt.logging.error(f"Failed to fetch credentials: {e}")


    def _check_account_status(self, credential, retries=3):
        if retries == 0:
            return 'skip'
        try:
            results = Search(credential['email'], credential['username'], credential['password'], save=False, debug=0).run(
                limit=1,
                retries=1,
                queries=[
                    {
                        'category': 'Latest',
                        'query': 'e'
                    }
                ]
            )[0]
        except Exception as ex:
            # bt.logging.error(f"({credential['username']}) Exception - {ex}")
            # print(ex.with_traceback())
            # if 'confirm_email' in str(ex):
            #     return 'email_verification'
            if 'confirmation code' in str(ex):
                return 'code_verification'
            elif 'flow_token' in str(ex):
                return 'skip'
            else:
                retries -= 1
                return self._check_account_status(credential, retries)
        if results['account_status'] != 'active':
            return results['account_status']
        else:
            if credential['status'] != 'active':
                self._update_credential_database(credential, 'active')
        return 'active'

    def _update_credential_database(self, credential, status):
        try:
            update_url = f"http://tstempmail1.pythonanywhere.com/api/credentials/{credential['id']}/"
            payload = {'status': status}
            response = requests.patch(update_url, json=payload)
            response.raise_for_status()
            bt.logging.info(f"Updated {credential['username']} status to {status}.")
        except requests.RequestException as e:
            bt.logging.error(f"Failed to update credential {credential['id']}: {e}")

    def release_credential(self, credential):
        """Function to unlock a specific credential using the API."""
        response = requests.post(f"http://tstempmail1.pythonanywhere.com/api/unlock_credential/{credential['username']}/")
        if response.status_code == 200:
            bt.logging.info(f"Credential {credential['username']} released.")
        else:
            bt.logging.info(f"Failed to release credential {credential['username']} - {response.text}") 
    
    def handle_locked_account(self, credential):
        self._update_credential_database(credential, 'locked')
        bt.logging.info(f"Removed and updated locked account: {credential['username']}")

class CredentialManager:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super(CredentialManager, cls).__new__(cls)
                    cls._instance._initialize()
        return cls._instance

    def _initialize(self):
        self.credentials = []
        self.credential_locks = {}
        self.access_lock = threading.Condition()
        self._get_and_filter_credentials()

    def _get_and_filter_credentials(self):
        try:
            response = requests.get("http://tstempmail1.pythonanywhere.com/api/credentials/")
            response.raise_for_status()
            fetched_credentials = response.json()
            active_credentials = [cred for cred in fetched_credentials if not self._is_locked(cred)]
            with self.access_lock:
                self.credentials = active_credentials
                self.credential_locks = {cred['id']: threading.Lock() for cred in self.credentials}
                bt.logging.info(f"Fetched {len(self.credentials)} active credentials from database.")
        except requests.RequestException as e:
            bt.logging.error(f"Failed to fetch credentials: {e}")

    def _is_locked(self, credential):
        return self._check_account_status(credential)

    def request_credential(self, _type = 'debug'):
        with self.access_lock:
            while not self.credentials:
                return None
            for credential in [c for c in self.credentials if c['ctype'] == _type]:
                if self._check_account_status(credential):
                    self.handle_locked_account(credential)
                lock = self.credential_locks[credential['id']]
                if lock.acquire(blocking=False):
                    self.credentials.remove(credential)
                    return credential
            return None

    def handle_locked_account(self, credential):
        with self.access_lock:
            if credential in self.credentials: 
                self.credentials.remove(credential)
                self._update_credential_database(credential, 'locked')
                bt.logging.info(f"Removed and updated locked account: {credential['username']}")


    def release_credential(self, credential):
        with self.access_lock:
            self.credentials.append(credential)
            self.credential_locks[credential['id']].release()
            self.access_lock.notifyAll()

    # Assuming this function checks the real-time status of the account and updates the database if locked
    def _check_account_status(self, credential, retries=3):
        if retries == 0:
            return True
        try:
            results = Search(credential['email'], credential['username'], credential['password'], save=False, debug=0).run(
                limit=1,
                retries=1,
                queries=[
                    {
                        'category': 'Latest',
                        'query': 'covid'
                    }
                ]
            )[0]
        except:
            retries -= 1
            return self._check_account_status(credential, retries)
        if results['account_status']:
            return True
        return False

    def _update_credential_database(self, credential, status):
        try:
            update_url = f"http://tstempmail1.pythonanywhere.com/api/credentials/{credential['id']}/"
            payload = {'status': status}
            response = requests.patch(update_url, json=payload)
            response.raise_for_status()
            bt.logging.info(f"Updated {credential['username']} status to {status}.")
        except requests.RequestException as e:
            bt.logging.error(f"Failed to update credential {credential['id']}: {e}")

class Search(Search):
    def __init__(self, email: str = None, username: str = None, password: str = None, session: search.Client = None, **kwargs):
        self.username = username
        # super().__init__(email, username, password, session, **kwargs)
        self.save = kwargs.get('save', True)
        self.debug = kwargs.get('debug', 0)
        self.logger = self._init_logger(**kwargs)
        self.session = self._validate_session(email, username, password, session, **kwargs)
        # bt.logging.error(f'session - {self.session}')
        # bt.logging.error(self.session.cookies.get('confirmation_code'))
    
    @staticmethod
    def _validate_session(*args, **kwargs):
        email, username, password, session = args

        # validate credentials
        if all((email, username, password)):
            return login_v2(email, username, password, **kwargs)

        # invalid credentials, try validating session
        if session and all(session.cookies.get(c) for c in {'ct0', 'auth_token'}):
            return session

        # invalid credentials and session
        cookies = kwargs.get('cookies')

        # try validating cookies dict
        if isinstance(cookies, dict) and all(cookies.get(c) for c in {'ct0', 'auth_token'}):
            _session = Client(cookies=cookies, follow_redirects=True)
            _session.headers.update(get_headers(_session))
            return _session

        # try validating cookies from file
        if isinstance(cookies, str):
            _session = Client(cookies=orjson.loads(Path(cookies).read_bytes()), follow_redirects=True)
            _session.headers.update(get_headers(_session))
            return _session

        raise Exception('Session not authenticated. '
                        'Please use an authenticated session or remove the `session` argument and try again.')

    async def paginate(self, client: AsyncClient, query: dict, limit: int, out: Path, **kwargs) -> list[dict]:
        params = {
            'variables': {
                'count': 20,
                'querySource': 'typed_query',
                'rawQuery': query['query'],
                'product': query['category']
            },
            'features': Operation.default_features,
            'fieldToggles': {'withArticleRichContentState': False},
        }

        res = []
        cursor = ''
        total = set()
        while True:
            if cursor:
                params['variables']['cursor'] = cursor
            data, entries, cursor, ratelimit, account_status = await self.backoff(lambda: self.get(client, params), **kwargs)
            res.extend(entries)
            if len(entries) <= 2 or len(total) >= limit or ratelimit or account_status!='active':  # just cursors
                if ratelimit:
                    self.debug and bt.logging.warning(f'[{RED} ({self.username}) RATE LIMIT EXCEEDED.')# Returned {len(total)} search results for {query["query"]}{RESET}]')
                elif account_status=='locked':
                    self.debug and bt.logging.warning(f'[{RED}fail{RESET}] ({self.username}) ACCOUNT LOCKED')
                elif self.session.cookies.get('confirmation_code') == 'true' or account_status=='confirmation_code':
                    bt.logging.warning(f'[{RED}fail{RESET}] ({self.username}) CONFIRMATION CODE REQUIRED FOR LOGGING IN')
                    account_status='code_verification'
                # elif self.session.cookies.get('confirm_email') == 'true' or account_status=='email_verification':
                #     bt.logging.error(f'[{RED}fail{RESET}] ({self.username}) IDENTITY VERIFICATION REQUIRED')
                #     account_status = 'email_verification'
                else:
                    account_status = 'active'
                self.debug and bt.logging.debug(
                    f'[{GREEN}success{RESET}]({self.username}) Returned {len(total)} search results for {query["query"]}')
                return {"data": res, "rate_limit": ratelimit, "account_status": account_status}
            total |= set(find_key(entries, 'entryId'))
            self.debug and bt.logging.debug(f'({self.username}) {query["query"]}')
            self.save and (out / f'{time.time_ns()}.json').write_bytes(orjson.dumps(entries))


    async def backoff(self, fn, **kwargs):
        retries = kwargs.get('retries', 3)
        entries = []
        for i in range(retries + 1):
            try:
                data, entries, cursor = await fn()
                if errors := data.get('errors'):
                    for e in errors:
                        if 'account is temporarily locked' in e.get('message'):
                            return data, entries, cursor, False, 'locked'
                        else:
                            # bt.logging.error(f'({self.username}) {e.get("message")}')
                            return data, entries, cursor, False, 'invalid_credential'
                elif self.session.cookies.get('confirmation_code') == 'true':
                    return  data, entries, cursor, False, 'code_verification'
                # elif self.session.cookies.get('confirm_email') == 'true':
                #     return  data, entries, cursor, False, 'email_verification'
                elif self.session.cookies.get('flow_errors') == 'true':
                    return  data, entries, cursor, False, 'invalid_credential'
                ids = set(find_key(data, 'entryId'))
                if len(ids) >= 2:
                    return data, entries, cursor, False, 'active'
            except Exception as e:
                if self.session.cookies.get('confirmation_code') == 'true':
                    return  None, [], None, False, 'code_verification'
                # elif self.session.cookies.get('confirm_email') == 'true':
                #     return  None, [], None, False, 'email_verification'
                elif self.session.cookies.get('flow_errors') == 'true':
                    return  None, [], None, False, 'invalid_credential'
                return None, [], None, True, 'active'

class TwitterScraper_V1:
    def __init__(self, limit=None, since_date=None, until_date=None, labels = None, uri=None, run_type='debug'):
        self.since_date = since_date
        self.until_date = until_date
        self.labels = labels
        self.uri = uri
        self.limit = limit
        self.since_id = None
        self.used_credentials = []
        self.blocked_credentials = []
        self.total_tweets = self.limit
        self.max_workers = 2
        self.run_type = run_type
        # if not labels:
        #     self.trending_hashtags = self.get_trending_hashtags()
        # else:
        #     self.trending_hashtags = None

    def query_generator(self, labels: list, since_date: datetime, until_date: datetime, since_id: str=None):
        date_format = "%Y-%m-%d_%H:%M:%S_UTC"
        query = f"since:{since_date.strftime(date_format)} until:{until_date.strftime(date_format)}"
        if labels:
            label_query = " OR ".join([label for label in labels])
            query += f" ({label_query})"
        else:
            query += " e"
            # label_query = " OR ".join([label for label in self.trending_hashtags[0:3]])
            # query += f" ({label_query})"
        if since_id:
            query = f"since_id:{since_id} " + query
        bt.logging.info(f"Generated query: {query}")
        return query

    def is_ratelimit_execeeded(self, credential):
        results = Search(credential['email'], credential['username'], credential['password'], save=False, debug=0).run(
                limit=1,
                retries=1,
                queries=[
                    {
                        'category': 'Latest',
                        'query': 'covid'
                    }
                ]
        )[0]
        if results['rate_limit']:
            return True
        return False    

    def search(self):
        data = []
        i = 0
        while True:
            credential = CredentialManager().request_credential()
            if not credential:
                bt.logging.warning(f"No available credentials. Commencing status verification for all accounts")
                CredentialManager_V2().verify_all_credentials()
                continue
            if self.is_ratelimit_execeeded(credential):
                CredentialManager().release_credential(credential)
                i+=1
                t = 2 * i + random.random()
                bt.logging.warning(f"Rate limit exceeded for username. Sleeping for {t} seconds.")
                time.sleep(t)
                continue
            i=1
            bt.logging.info(f"Using username {credential['username']}.")
            try:
                sc = Search(credential['email'], credential['username'], credential['password'], save=False, debug=1)
                results = sc.run(
                    limit=self.limit,
                    retries=self.limit,
                    queries=[
                        {
                            'category': 'Latest',
                            'query': self.query_generator(self.labels, self.since_date, self.until_date, self.since_id)
                        }
                    ]
                )[0]
            except Exception as ex:
                bt.logging.error(f"Error occurred while scraping: {ex}")
                CredentialManager().release_credential(credential)
                continue
            CredentialManager().release_credential(credential)
            bt.logging.info(f"Scraped {len(results['data'])} tweets using username {credential['username']}. Total tweets scraped = {len(data)}")
            if results['account_status']:
                if results['data']:
                    self.total_tweets -= len(results['data'])
                    self.limit -= len(results['data'])
                    self.since_date = datetime.strptime(results['data'][-1]['content']['itemContent']['tweet_results']['result']['legacy']["created_at"], "%a %b %d %H:%M:%S %z %Y") #+ timedelta(miliseconds=1)
                    self.since_id = results['data'][-1]['content']['itemContent']['tweet_results']['result']['legacy']["id_str"]
                    data.extend(results['data'])
                bt.logging.warning(f"Account {credential['username']} is locked. Removing from credentials database.")
                CredentialManager().handle_locked_account(credential)
                continue
            elif results['rate_limit']:
                if results['data']:
                    self.total_tweets -= len(results['data'])
                    self.limit -= len(results['data'])
                    self.since_date = datetime.strptime(results['data'][-1]['content']['itemContent']['tweet_results']['result']['legacy']["created_at"], "%a %b %d %H:%M:%S %z %Y") #+ timedelta(miliseconds=1)
                    self.since_id = results['data'][-1]['content']['itemContent']['tweet_results']['result']['legacy']["id_str"]
                    data.extend(results['data'])
                # bt.logging.info(f"Scraped {len(results['data'])} tweets using username {credential['username']}. Total tweets scraped = {len(data)}")
                continue
            else:
                data.extend(results['data'])
                # bt.logging.info(f"Scraped {len(results['data'])} tweets using username {credential['username']}. Total tweets scraped = {len(data)}")
                return data

    def tweet(self):
        credential = random.choice(self.credentials)
        sc = scraper.Scraper(credential['email'], credential['username'], credential['password'], save=False, debug=0)
        tweet_id = self.uri.split('/')[-1]
        result = sc.tweets_by_ids([tweet_id])
        return result

    def search_v2(self):
        data = []
        i = 0
        while True:
            credential = CredentialManager_V2().request_credential(self.run_type)
            if not credential:
                i+=1
                t = 2 * i + random.random()
                bt.logging.warning(f" No available credentials. Sleeping for {t} seconds.")
                time.sleep(t)
                continue
            if self.is_ratelimit_execeeded(credential):
                CredentialManager_V2().release_credential(credential)
                i+=1
                t = 2 * i + random.random()
                bt.logging.warning(f" Rate limit exceeded for username. Sleeping for {t} seconds.")
                time.sleep(t)
                continue
            i=1
            bt.logging.info(f"Using username {credential['username']}.")
            try:
                sc = Search(credential['email'], credential['username'], credential['password'], save=False, debug=1)
                results = sc.run(
                    limit=self.limit,
                    retries=self.limit,
                    queries=[
                        {
                            'category': 'Latest',
                            'query': self.query_generator(self.labels, self.since_date, self.until_date, self.since_id)
                        }
                    ]
                )[0]
            except Exception as ex:
                bt.logging.error(f" Error occurred while scraping: {ex}")
                CredentialManager_V2().release_credential(credential)
                continue
            CredentialManager_V2().release_credential(credential)
            data.extend(results['data'])
            bt.logging.info(f" Scraped {len(results['data'])} tweets using username {credential['username']}. Total tweets scraped = {len(data)}")
            if results['account_status'] != 'active':
                if results['data']:
                    self.total_tweets -= len(results['data'])
                    self.limit -= len(results['data'])
                    self.since_date = datetime.strptime(results['data'][-1]['content']['itemContent']['tweet_results']['result']['legacy']["created_at"], "%a %b %d %H:%M:%S %z %Y") #+ timedelta(miliseconds=1)
                    self.since_id = results['data'][-1]['content']['itemContent']['tweet_results']['result']['legacy']["id_str"]
                    # data.extend(results['data'])
                bt.logging.warning(f" Account {credential['username']} is locked. Removing from credentials database.")
                CredentialManager_V2()._update_credential_database(credential, results['account_status'])
                CredentialManager_V2().release_credential(credential)
                continue
            elif results['rate_limit']:
                if results['data']:
                    self.total_tweets -= len(results['data'])
                    self.limit -= len(results['data'])
                    self.since_date = datetime.strptime(results['data'][-1]['content']['itemContent']['tweet_results']['result']['legacy']["created_at"], "%a %b %d %H:%M:%S %z %Y") #+ timedelta(miliseconds=1)
                    self.since_id = results['data'][-1]['content']['itemContent']['tweet_results']['result']['legacy']["id_str"]
                    # data.extend(results['data'])
                # bt.logging.info(f"Scraped {len(results['data'])} tweets using username {credential['username']}. Total tweets scraped = {len(data)}")
                continue
            else:
                # data.extend(results['data'])
                # bt.logging.info(f"Scraped {len(results['data'])} tweets using username {credential['username']}. Total tweets scraped = {len(data)}")
                return data

    def get_trending_hashtags(self):
        while True:
            credential = CredentialManager_V2().request_credential(self.run_type)
            if not credential:
                i+=1
                t = 2 ** i + random.random()
                bt.logging.warning(f" No available credentials. Sleeping for {t} seconds.")
                time.sleep(t)
                continue
            if self.is_ratelimit_execeeded(credential):
                CredentialManager_V2().release_credential(credential)
                i+=1
                t = 2 ** i + random.random()
                bt.logging.warning(f" Rate limit exceeded for username. Sleeping for {t} seconds.")
                time.sleep(t)
                continue
            i=1
            bt.logging.info(f"Using username {credential['username']} for fetching trending_hashtag.")
            sc = scraper.Scraper(credential['email'], credential['username'], credential['password'], save=False, debug=0)
            result = sc.trends(['+0530'])[0]
            CredentialManager_V2().release_credential(credential)
            trending_hashtags = result.keys()
            return list(trending_hashtags)
        # return sc.trends(['+0530'])

# generated_id = []
def get_tweets_for_time_window(start, end, limit, labels, run_type):
    # global generated_id
    # while True:
    #     id = random.randint(1, 100000)
    #     if id not in generated_id:
    #         generated_id.append(id)
    #         break
    scraper = TwitterScraper_V1(
        since_date=start,
        until_date=end,
        limit=limit,
        labels=labels,
        run_type=run_type
    )
    return scraper.search_v2()

def divide_time_into_windows(start_date, end_date, number_of_windows):
    total_duration = end_date - start_date
    if number_of_windows > 1:
        window_duration = total_duration / number_of_windows
    else:
        window_duration = total_duration
    windows = []
    current_start = start_date
    for _ in range(number_of_windows):
        current_end = current_start + window_duration
        if current_end > end_date:
            current_end = end_date
        windows.append((current_start, current_end))
        current_start = current_end
    return windows


def fetch_tweets_in_parallel(since_date, until_date, labels, max_items=100, max_workers=2, run_type='production'):
    all_tweets = []
    time_windows = divide_time_into_windows(since_date, until_date, max_workers)
    try:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_time_window = {executor.submit(get_tweets_for_time_window, start, end, int(max_items/max_workers), labels, run_type): (start, end) for start, end in time_windows}
            for future in as_completed(future_to_time_window):
                time_window = future_to_time_window[future]
                try:
                    tweets_data = future.result()
                    all_tweets.extend(tweets_data)
                    # print(f"Successfully fetched data for {time_window}: {tweets_data}")
                except Exception as exc:
                    print(f"Failed to fetch data for {time_window}: {exc}")
        
        bt.logging.info(f"Total tweets fetched: {len(all_tweets)}")
    except Exception as e:
        bt.logging.error(f"parallel search failed: {e}")
    return all_tweets
    

if __name__ == '__main__':
    start = datetime.now()
    CredentialManager_V2().verify_all_credentials()
    # c = CredentialManager_V2().request_credential(_type='all')
    # print(c)
    # CredentialManager_V2().release_credential(c)
    # print(Search('tstempmail1@proton.me', 'AlexFergus67516', 'iball123', save=False, debug=1).run(limit=1,
    #             retries=1,
    #             queries=[
    #                 {
    #                     'category': 'Latest',
    #                     'query': 'covid'
    #                 }
    #             ]))
    # print(len(TwitterScraper_V1(labels=['covid'], limit=4000, since_date=datetime(2023, 1, 1), until_date=datetime(2023, 2, 1)).search()))
    # fetch_tweets_in_parallel(datetime(2024, 3, 12), datetime(2024, 3, 14), labels=[], max_items=10000, max_workers=1,run_type='production')
    # TwitterScraper_V1(labels=['#MUFC'], limit=1000, since_date=datetime(2024, 1, 1), until_date=datetime(2024, 3, 1)).trending_hashtags()
    print("Time Taken to scrape: ", (datetime.now() - start).seconds/60)
    # # print(len(search_scrape_v2('since:2023-01-01_00:00:00_UTC until:2023-02-01_00:00:00_UTC covid', 1000)))
    # # print(tweet_scrape('https://twitter.com/realDonaldTrump/status/1255230848343981056'))
    # # print(trending_hashtags())
    # asyncio.run(TwitterScraper('covid', 100).search())
    pass

# def search_scrape(query, max_items):
#     # credentials = json.load(open('scraping/x/x_credentials.json', 'r'))
#     global credentials
#     credential = random.choice(credentials['x_credentials'])
#     # print(credential)
#     sc = search.Search(credential['email'], credential['username'], credential['password'], save=False, debug=1)
#     return sc.run(
#         limit=max_items,
#         retries=max_items,
#         queries=[
#             {
#                 'category': 'Latest',
#                 'query': query
#             }
#         ]
#     )[0]

# def tweet_scrape(uri:str):
#     # credentials = json.load(open('scraping/x/x_credentials.json', 'r'))
#     global credentials
#     sc = scraper.Scraper(credentials['x_credentials']['email'], credentials['x_credentials']['username'], credentials['x_credentials']['password'], save=False, debug=0)
#     tweet_id = uri.split('/')[-1]
#     return sc.tweets_by_ids([tweet_id])


