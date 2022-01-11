#!/bin/env python3.9
from slack_sdk.web.client import WebClient
from gtasks import *

import hashlib
import configparser
import sys
import pathlib
import time
import string
import os
import tempfile
import re
import json
import uuid
from typing import Tuple, List
from pathlib import Path
from datetime import datetime, timezone

import click
import boto3
from newspaper.utils import memoize_articles
import schedule
from botocore.exceptions import (
    ClientError as BotoClientError,
    MissingDependencyException,
)
from selenium.webdriver.firefox.firefox_profile import FirefoxProfile
from selenium.webdriver.firefox.firefox_binary import FirefoxBinary
from selenium.webdriver.firefox.webdriver import WebDriver
from sty import fg, bg, ef, rs
from newspaper import Article as N3kArticle
from selenium import webdriver as wd
from pocket import Pocket, PocketException
from loguru import logger
from jinja2 import Template
from urllib.parse import urlparse, urljoin
from slack_bolt import App as SlackApp, app
from slack_bolt.adapter.socket_mode import SocketModeHandler as SlackSocketModeHandler

######################################
# init
######################################
INSTANCE_UUID = str(uuid.uuid4())

# config
config_file = pathlib.Path(__file__).parent.resolve().joinpath("settings.cfg")
if not config_file.exists():
    raise Exception("settings.cfg missing")
config = configparser.ConfigParser(
    converters={"list": lambda x: [i.strip() for i in x.split(",")]}
)
config.read(str(config_file))

# logging
BASE_LOG_PATH = pathlib.Path(config.get("logging", "base_path"))

if not BASE_LOG_PATH.exists():
    raise Exception("Cannot find logging path")
app_name = pathlib.Path(__file__).name.replace(".py", "")
app_log_path = BASE_LOG_PATH.joinpath(app_name)
app_log_path.mkdir(exist_ok=True)
app_log_path = app_log_path.joinpath(f"{app_name}.log")
logger.add(
    str(app_log_path),
    rotation=config.get("logging", "rotation"),
    retention=config.get("logging", "retention"),
    compression=config.get("logging", "compression"),
)

# selenium
SELENIUM_LOG_ENABLED = False
SELENIUM_FIREFOX_PROFILE_PATH = ""
SELENIUM_USE_USER_DEFAULT_FIREFOX_PROFILE = False
if config.has_section("selenium"):
    if config.has_option("selenium", "selenium_log_enabled"):
        SELENIUM_LOG_ENABLED = config.getboolean("selenium", "selenium_log_enabled")
    if config.has_option("selenium", "firefox_profile_path"):
        SELENIUM_FIREFOX_PROFILE_PATH = config.get("selenium", "firefox_profile_path")
    if config.has_option("selenium", "selenium_use_user_default_firefox_profile"):
        SELENIUM_USE_USER_DEFAULT_FIREFOX_PROFILE = config.getboolean(
            "selenium", "selenium_use_user_default_firefox_profile"
        )

# aws
AWS_CONFIG = None
AWS_S3_BUCKET_NAME = None
AWS_S3_BUCKET_IS_DOMAIN_ALIAS = False
aws_access_key_id = None
aws_secret_access_key = None
if config.has_section("aws"):
    if config.has_option("aws", "aws_access_key_id"):
        aws_access_key_id = config.get("aws", "aws_access_key_id")
    if config.has_option("aws", "aws_secret_access_key"):
        aws_secret_access_key = config.get("aws", "aws_secret_access_key")

    if aws_access_key_id is not None and aws_secret_access_key is not None:
        AWS_CONFIG = {
            "aws_access_key_id": aws_access_key_id,
            "aws_secret_access_key": aws_secret_access_key,
        }
if config.has_section("aws.s3"):
    if config.has_option("aws.s3", "bucket_name"):
        AWS_S3_BUCKET_NAME = config.get("aws.s3", "bucket_name")
    if config.has_option("aws.s3", "bucket_is_domain_alias"):
        AWS_S3_BUCKET_IS_DOMAIN_ALIAS = config.getboolean(
            "aws.s3", "bucket_is_domain_alias"
        )

# google tasks
GTASK_CLIENT_CONFIG = None
GTASK_LIST_NAME = None
google_redirect_uris = None
google_client_id = None
google_client_secret = None
google_auth_uri = None
google_token_uri = None
if config.has_section("google"):
    if config.has_option("google", "redirect_uris"):
        google_redirect_uris = list(map(str, config.getlist("google", "redirect_uris")))
    if config.has_option("google", "client_id"):
        google_client_id = config.get("google", "client_id")
    if config.has_option("google", "client_secret"):
        google_client_secret = config.get("google", "client_secret")
    if config.has_option("google", "auth_uri"):
        google_auth_uri = config.get("google", "auth_uri")
    if config.has_option("google", "token_uri"):
        google_token_uri = config.get("google", "token_uri")

    if (
        google_redirect_uris is not None
        and google_client_id is not None
        and google_client_secret is not None
        and google_auth_uri is not None
        and google_token_uri is not None
    ):
        GTASK_CLIENT_CONFIG = {
            "installed": {
                "client_id": google_client_id,
                "client_secret": google_client_secret,
                "redirect_uris": google_redirect_uris,
                "auth_uri": google_auth_uri,
                "token_uri": google_token_uri,
            }
        }
if config.has_section("google.tasks"):
    if config.has_option("google.tasks", "task_list"):
        GTASK_LIST_NAME = config.get("google.tasks", "task_list")

# pocket
POCKET_CONSUMER_KEY = None
POCKET_ACCESS_TOKEN = None
if config.has_section("pocket"):
    if config.has_option("pocket", "pocket_consumer_key"):
        POCKET_CONSUMER_KEY = config.get("pocket", "pocket_consumer_key")
    if config.has_option("pocket", "pocket_access_token"):
        POCKET_ACCESS_TOKEN = config.get("pocket", "pocket_access_token")

# slack
SLACK_BOT_TOKEN = None
SLACK_APP_TOKEN = None
if config.has_section("slack"):
    if config.has_option("slack", "bot_token"):
        SLACK_BOT_TOKEN = config.get("slack", "bot_token")
    if config.has_option("slack", "app_token"):
        SLACK_APP_TOKEN = config.get("slack", "app_token")

######################################
# funcs
######################################
def get_aws_client(service: str):
    aws_client = None
    if AWS_CONFIG is None:
        logger.debug("attempting to use aws with .aws credentials")
        aws_client = boto3.client(service)
    else:
        logger.debug("using credentials from settings")
        aws_client = boto3.client(service, **AWS_CONFIG)

    if aws_client is None:
        raise Exception("could not establish aws connection")

    return aws_client


def get_gtask():
    if GTASK_CLIENT_CONFIG is not None:
        return gtasks(client=GTASK_CLIENT_CONFIG)
    else:
        return gtasks()


def get_pocket_client():
    if POCKET_CONSUMER_KEY is not None and POCKET_ACCESS_TOKEN is not None:
        return Pocket(POCKET_CONSUMER_KEY, POCKET_ACCESS_TOKEN)
    else:
        raise Exception("Pocket consumer and access token not specified")


def get_slack_app() -> SlackApp:
    if SLACK_BOT_TOKEN is not None and SLACK_APP_TOKEN is not None:
        slack_app = SlackApp(token=SLACK_BOT_TOKEN)
        return slack_app
    else:
        raise ValueError("slack config missing")


def test_creds(
    test_s3: bool = False, test_gtask: bool = False, test_pocket: bool = False
):
    if test_s3:
        print(f"{fg.cyan}testing {fg.yellow}AWS S3{fg.rs}")
        print(
            f"  {fg.green}fetching bucket website {fg.yellow}{AWS_S3_BUCKET_NAME}{fg.rs}"
        )
        bucket_website_exists, bucket_website_url = get_s3_website_Url(
            AWS_S3_BUCKET_NAME
        )
        if bucket_website_exists:
            print(
                f"  👍 {fg.green}bucket website: {fg.yellow}{bucket_website_url}{fg.rs}"
            )
        else:
            print(f"  {fg.red}could not find s3 bucket website{fg.rs}")
    if test_gtask:
        print(f"{fg.cyan}testing {fg.yellow}Google Tasks{fg.rs}")
        gt = get_gtask()
        print(f"  {fg.green}fetching list {fg.yellow}{GTASK_LIST_NAME}{fg.rs}")
        print(f"  {fg.green}fetching task list: {fg.yellow}{GTASK_LIST_NAME}{fg.rs}")
        gtask_list = gt.get_list(GTASK_LIST_NAME)
        print(
            f"  👍 {fg.green}task list id: {fg.yellow}{gtask_list._task_list['id']}{fg.rs}"
        )
    if test_pocket:
        print(f"{fg.cyan}testing {fg.yellow}Pocket{fg.rs}")
        p = get_pocket_client()
        test_url = "https://neemblog.home.blog/2020/08/19/the-lost-art-of-fan-made-anime-trollsubs/"
        print(f"  {fg.green}adding test url: {fg.yellow}{test_url}{fg.rs}")
        p.add(url=test_url, tags=["readcli", "auto"])
        print(f"  👍 {fg.green}OK{fg.rs}")


def new_ff_browser(
    *ignore, mobile_user_agent: bool = False, print_pdf_filename: str = "print.pdf"
) -> WebDriver:
    ff_opts = wd.FirefoxOptions()
    ff_opts.headless = True
    ff_opts.accept_insecure_certs = True
    mobile_user_agent = "Mozilla/5.0 (iPhone; CPU iPhone OS 12_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/13.2b11866 Mobile/16A366 Safari/605.1.15"

    # print to PDF
    # https://stackoverflow.com/questions/68788695/how-to-handle-firefox-print-dialog-box-in-selenium
    # You can see/play with these settings in about:config
    # Also "more settings" section under the print dialog
    ff_opts.set_preference("print_printer", "Mozilla Save to PDF")
    ff_opts.set_preference("print.always_print_silent", True)
    ff_opts.set_preference("print.show_print_progress", False)
    ff_opts.set_preference("print.save_as_pdf.links.enabled", True)
    ff_opts.set_preference("print.printer_Mozilla_Save_to_PDF.print_to_file", True)
    ff_opts.set_preference(
        "print.printer_Mozilla_Save_to_PDF.print_to_filename", print_pdf_filename
    )

    # look for bin files relative to script
    #   bin/firefox/firefox
    #   bin/geckodriver
    ff_bin = pathlib.Path(__file__).parent.joinpath("bin/firefox/firefox")
    geckodriver_bin = pathlib.Path(__file__).parent.joinpath("bin/geckodriver")
    if not ff_bin.exists():
        raise Exception("firefox not found at bin/firefox/firefox")
    if not geckodriver_bin.exists():
        raise Exception("geckodriver not found at bin/geckodriver")
    ff_bin = FirefoxBinary(str(ff_bin))
    ff_opts.binary = ff_bin

    # determine firefox profile to use
    _firefox_profile_path = ""
    if SELENIUM_USE_USER_DEFAULT_FIREFOX_PROFILE:
        default_profile = list(Path.home().glob(".mozilla/firefox/*.default-release"))
        if len(default_profile) == 1:
            _firefox_profile_path = str(default_profile[0])
            logger.debug(f"using default profile: {_firefox_profile_path}")
        else:
            logger.debug(f"cannot find default firefox profiles for user.")
    elif len(SELENIUM_FIREFOX_PROFILE_PATH) > 0:
        if pathlib.Path(SELENIUM_FIREFOX_PROFILE_PATH).exists():
            _firefox_profile_path = SELENIUM_FIREFOX_PROFILE_PATH
            logger.debug(f"using profile: {_firefox_profile_path}")
        else:
            logger.debug(
                f"could not find profile path: {SELENIUM_FIREFOX_PROFILE_PATH}"
            )
    logger.debug(f"firefox log path: {_firefox_profile_path}")

    # set selenium log
    selenium_log_path = "/dev/null"
    if SELENIUM_LOG_ENABLED:
        selenium_log_path = pathlib.Path.joinpath(BASE_LOG_PATH, "geckodriver.log")
        logger.info(f"selenium log: {selenium_log_path}")
    else:
        logger.info("disabling selenium logs")

    # browser profile
    ff_profile = None
    if len(_firefox_profile_path) > 0:
        ff_profile_copy = FirefoxProfile(_firefox_profile_path)
        ff_profile = ff_profile_copy
    else:
        ff_profile = FirefoxProfile()

    ff_profile.set_preference("xpinstall.signatures.required", False)
    if mobile_user_agent:
        ff_profile.set_preference("general.useragent.override", mobile_user_agent)
    ff_opts.profile = ff_profile

    # browser
    browser_kwargs = {
        "executable_path": str(geckodriver_bin),
        "options": ff_opts,
        "service_log_path": selenium_log_path,
    }
    browser = wd.Firefox(**browser_kwargs)

    # install xpi addons
    xpi_files = [f for f in pathlib.Path(__file__).resolve().parent.glob("xpi/*.xpi")]
    for xpi_file in xpi_files:
        browser.install_addon(
            path=str(xpi_file), temporary=True
        )  # for some reason FireFoxProfile.add_extension() doesn't work.

    # for some reason navigating to this page (any page?) helps bypass-firewall load correctly
    browser.get("about:support")

    return browser


def get_ff_screenshot_data_png(browser: WebDriver, width: int = 900, height: int = -1):
    if height == -1:
        height = browser.execute_script("return document.body.scrollHeight")
    browser.set_window_size(width, height)
    return browser.get_screenshot_as_png()


def wait_file_change(
    *ignore,
    file_path: str = "",
    intervals: int = 40,
    interval_sec: int = 0.5,
    same_size_threshold: int = 3,
) -> None:
    if len(file_path) == 0:
        raise TypeError("file_path is empty")
    file = pathlib.Path(file_path)

    last_size = -1
    same_size_count = 0
    for i in range(1, intervals + 1):
        curr_size = -1
        if file.exists():
            curr_size = file.stat().st_size
            logger.debug(f"{i}/{intervals} {file} is size {curr_size}")
            if curr_size == last_size:
                same_size_count = same_size_count + 1
                logger.debug(
                    f"{i}/{intervals} {file} is same size {same_size_count}/{same_size_threshold}"
                )
                if same_size_count == same_size_threshold:
                    break
            else:
                same_size_count = 0
        else:
            logger.debug(f"{i}/{intervals} {file} does not exist")

        if curr_size > 0:
            last_size = curr_size
        time.sleep(interval_sec)


def get_page_content(
    url: str,
    retries: int = 3,
    min_parsed_length_chars: int = 600,
    clean_article: bool = True,
    return_objects: bool = False,
    retry_interval_sec: int = 5,
):
    browser = None
    parsed_success = False
    browser_source = ""
    article = None
    screenshot_data = None
    tmp_dir = None
    try:
        is_printing = True
        print_pdf_file = pathlib.Path("/tmp").joinpath(f"scrape_{INSTANCE_UUID}.pdf")
        browser = new_ff_browser(print_pdf_filename=str(print_pdf_file))
        for t in range(retries):
            # get page HTML
            browser_source = ""
            browser.get(url)
            logger.info(f"{t+1}/{retries} scrape returned {len(browser.page_source)}")
            if len(browser.page_source) == 0:
                continue
            browser_source = browser.page_source

            # take screenshot
            logger.info(f"{t+1}/{retries} taking screenshot")
            screenshot_data = get_ff_screenshot_data_png(browser=browser)

            # print to pdf
            logger.info(f"{t+1}/{retries} printing pdf: {print_pdf_file}")
            try:
                print_pdf_file.unlink(missing_ok=True)
                browser.execute_script("window.print()")
                is_printing = True
            except:
                logger.exception("issue printing pdf")

            if is_printing:
                # time.sleep(10)
                wait_file_change(file_path=str(print_pdf_file))
                print(f"hi {print_pdf_file.exists()}")

            # newspaper3k parse
            article = N3kArticle("", languages="en", memoize_articles=False)
            article.download(input_html=browser_source)
            article.parse()
            logger.info(f"{t+1}/{retries} n3k parse returned {len(article.text)} chars")
            if len(article.text) < min_parsed_length_chars:
                logger.info(
                    f"{t+1}/{retries} min chars not met: {min_parsed_length_chars}, waiting {retry_interval_sec}s"
                )
                logger.debug(f"parsed text:\n{article.text}")
                time.sleep(retry_interval_sec)
            else:
                logger.info(f"{t+1}/{retries} parse OK")
                parsed_success = True
                break
    except Exception:
        raise
    finally:
        if browser is not None:
            browser.quit()

    if return_objects:
        return browser_source, article

    if parsed_success:
        text = article.text
        if clean_article:
            text = remove_empty_space(article.text)
        return text, article, screenshot_data, print_pdf_file
    return None, None, None, None


def get_s3_website_Url(bucket: str) -> Tuple[bool, str]:
    bucket_website_exists = False
    bucket_website_Url = ""
    s3_client = get_aws_client("s3")
    logger.debug(f"looing up bucket: {bucket}")
    try:
        foo = s3_client.get_bucket_website(Bucket=bucket)
        bucket_website_exists = True
    except:
        logger.exception("Could not get s3 website")
        bucket_website_exists = False

    if bucket_website_exists:
        if AWS_S3_BUCKET_IS_DOMAIN_ALIAS:
            bucket_website_Url = f"http://{str.lower(bucket)}"
        else:
            bucket_loc = s3_client.get_bucket_location(Bucket=bucket)
            bucket_region = bucket_loc["LocationConstraint"]
            bucket_website_Url = (
                f"http://{bucket}.s3-website.{bucket_region}.amazonaws.com"
            )

    return bucket_website_exists, bucket_website_Url


def format_filename(s):
    valid_chars = "-_.() %s%s" % (string.ascii_letters, string.digits)
    filename = "".join(c for c in s if c in valid_chars)
    filename = filename.replace(" ", "_")
    return filename


def remove_empty_space(text: str):
    lines = []
    prevLine = None
    for line in text.split("\n"):
        if line.strip() != "":
            # include empty lines when they're proceeded by non-empty ones
            # this accounts for the "paragraph" convention.
            if prevLine != None and prevLine.strip() == "":
                lines.append("")
            lines.append(line)
        prevLine = line

    return "\n".join(lines)


def format_article_html2(
    *ignore, s3_url: str, url: str, text: str, base_name: str, article: N3kArticle
):
    template_file = pathlib.Path(__file__).parent.joinpath("article.html.j2")
    if not template_file.exists():
        raise MissingDependencyException("article.html.j2 missing")
    template_str = template_file.read_text()

    authors_csv = "unknown"
    publish_date_str = "unknown"
    published_date_iso = ""
    if article.publish_date is not None:
        publish_date_str = article.publish_date.strftime("%A %b %d, %Y @ %H:%M:%S")
        published_date_iso = article.publish_date.isoformat()
    if len(article.authors) > 0:
        authors_csv = ", ".join(article.authors)

    template_data = {
        "s3_url": s3_url,
        "article": article,
        "article_paragraphs": text.split("\n\n"),
        "website": (urlparse(url)).netloc,
        "authors_csv": authors_csv,
        "publish_date_str": publish_date_str,
        "published_date_iso": published_date_iso,
        "parsed_on": datetime.now(timezone.utc).isoformat(),
        "url": url,
        "base_name": base_name,
    }

    j2_template = Template(template_str)
    return str.strip(j2_template.render(template_data))


def create_pocket_access_token(
    pocket_consumer_key: str, pocket_redirect_uri: str = "http://foo.bar/"
):
    # Validate params and existing values
    print(fg.green + "starting pocket auth process ..." + fg.rs)
    existing_pocket_access_token = os.getenv("READCLI_POCKET_ACCESS_TOKEN", "")
    if len(pocket_consumer_key) == 0:
        print(fg.red + "pocket consumer key is not defined" + fg.rs)
    if len(existing_pocket_access_token) > 0:
        while True:
            print(
                fg.yellow
                + "READCLI_POCKET_ACCESS_TOKEN already defined. Are you sure you want to continue?"
                + fg.rs
            )
            print(
                fg.cyan + "Type yes to continue or CTRL+C to cancel: " + fg.rs, end=""
            )
            ans = input()
            if (ans.strip().lower()) == "yes":
                break

    # Get a request token
    print(fg.green + "getting request token" + fg.rs)
    request_token = Pocket.get_request_token(
        consumer_key=pocket_consumer_key, redirect_uri=pocket_redirect_uri
    )

    # Get an auth url to present to the user
    print(fg.green + "getting authorization url" + fg.rs)
    auth_url = Pocket.get_auth_url(code=request_token, redirect_uri=pocket_redirect_uri)

    # Prompt the user to enter the url manually
    print(fg.green + "waiting for user action ..." + fg.rs)
    print(fg.yellow + "please visit in your browser." + fg.rs)
    print(fg.magenta + auth_url + fg.rs)
    print(
        fg.yellow
        + "you will be redirected to this url when done: "
        + fg.da_yellow
        + pocket_redirect_uri
        + fg.rs
    )
    print("")
    while True:
        print(fg.cyan + "Type yes to continue or CTRL+C to cancel: " + fg.rs, end="")
        ans = input()
        if (ans.strip().lower()) == "yes":
            break

    # Get authorized request token
    user_credentials = Pocket.get_credentials(
        consumer_key=pocket_consumer_key, code=request_token
    )
    access_token = user_credentials["access_token"]
    print(fg.li_green + "your access token is: " + fg.li_yellow + access_token + fg.rs)
    print(
        fg.li_green
        + "add to your ~/.bashrc: "
        + fg.li_yellow
        + f"READCLI_POCKET_ACCESS_TOKEN={access_token}"
        + fg.rs
    )


def validate_url(url: str):
    url_regex = re.compile(
        r"^(?:http|ftp)s?://"  # http:// or https://
        r"(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|"  # domain...
        r"localhost|"  # localhost...
        r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"  # ...or ip
        r"(?::\d+)?"  # optional port
        r"(?:/?|[/?]\S+)$",
        re.IGNORECASE,
    )
    return re.match(url_regex, url) is not None


def short_str(s, char_length=8):
    if char_length > 128:
        raise ValueError("char_length {} exceeds 128".format(char_length))
    hash_object = hashlib.sha512(s.encode())
    hash_hex = hash_object.hexdigest()
    return hash_hex[0:char_length]


def scrape_url(
    url: str, print_article: bool, print_html: bool, push_pocket: bool, retries: int = 3
) -> str:
    html_text = ""
    url = str.strip(url)
    if not validate_url(url):
        logger.error(f"url invalid: {url}")

    url_cleaned = urljoin(url, urlparse(url).path)

    # scrape and process article
    plain_text, article, screenshot_data, print_pdf_file = get_page_content(
        url=url_cleaned, retries=retries
    )
    if plain_text is None or len(plain_text) == 0:
        logger.critical(f"Could not scrape url: {url_cleaned}")
        return

    # print article to console
    if print_article:
        print("")
        print(fg.cyan + "----- BEGIN ARTICLE -----" + fg.rs)
        print(fg.cyan + "TITLE: " + article.title + fg.rs)
        print(fg.cyan + "BY: " + (", ".join(article.authors)) + fg.rs)
        print(fg.cyan + "PUBLISHED: " + str(article.publish_date) + fg.rs)
        print(plain_text)
        print(fg.cyan + "----- END ARTICLE -----" + fg.rs)

    if print_html:
        html_text = format_article_html2(
            s3_url="[placeholder]", url=url_cleaned, text=plain_text, article=article
        )
        print(fg.li_cyan + "----- BEGIN HTML -----" + fg.rs)
        print(html_text)
        print(fg.li_cyan + "----- END HTML -----" + fg.rs)

    # upload to s3 and then queue to pocket
    if push_pocket:
        s3_url = ""
        logger.info(f"uploading to S3 bucket {AWS_S3_BUCKET_NAME}")

        # Make sure bucket has S3 Website feature enabled
        s3_website_exists, s3_website_Url = get_s3_website_Url(
            bucket=AWS_S3_BUCKET_NAME
        )
        if not s3_website_exists:
            logger.critical(
                f"s3 website for '{AWS_S3_BUCKET_NAME}' does not exist. You may need to enable this."
            )

        # upload
        s3_client = get_aws_client("s3")
        file_basename = str.lower(format_filename(article.title))
        short_hash = short_str(url_cleaned)
        base_name = f"{file_basename}_{short_hash}"
        base_key = f"cp/{base_name}"
        html_filekey = f"{base_key}/index.html"
        screenshot_filekey = f"{base_key}/{base_name}.png"
        pdf_filekey = f"{base_key}/{base_name}.pdf"
        s3_url = f"{s3_website_Url}/{base_key}/"

        # create html
        html_text = format_article_html2(
            s3_url=s3_url,
            url=url_cleaned,
            text=plain_text,
            base_name=base_name,
            article=article,
        )

        # create s3 subfolder
        s3_client.put_object(Bucket=AWS_S3_BUCKET_NAME, Key=f"{base_key}/")

        # upload files
        tmp_dir = None
        try:
            tmp_dir = tempfile.TemporaryDirectory()

            # upload screenshot
            tmp_screenshot_file = pathlib.Path(tmp_dir.name).joinpath("tmp.png")
            tmp_screenshot_file.write_bytes(screenshot_data)
            logger.info(f"uploading screenshot: {screenshot_filekey}")
            s3_client.upload_file(
                str(tmp_screenshot_file),
                AWS_S3_BUCKET_NAME,
                screenshot_filekey,
                ExtraArgs={"ContentType": "image/png"},
            )

            # upload pdf
            if print_pdf_file.exists():
                logger.info(f"uploading pdf: {pdf_filekey}")
                s3_client.upload_file(
                    str(print_pdf_file),
                    AWS_S3_BUCKET_NAME,
                    pdf_filekey,
                    ExtraArgs={"ContentType": "application/pdf"},
                )

            # upload HTML to s3 bucket
            tmp_html_file = pathlib.Path(tmp_dir.name).joinpath("tmp.html")
            tmp_html_file.write_text(html_text)
            logger.info(f"uploading HTML: {html_filekey}")
            s3_client.upload_file(
                str(tmp_html_file),
                AWS_S3_BUCKET_NAME,
                html_filekey,
                ExtraArgs={"ContentType": "text/html"},
            )
        except:
            raise
        finally:
            if tmp_dir is not None:
                tmp_dir.cleanup()

        # add to pocket
        logger.info(f"adding item to pocket title:'{article.title}',url:{s3_url}")
        p = get_pocket_client()
        p.add(url=s3_url, Title=article.title, tags=["readcli", "auto"])

        return s3_url

    # cleanup pdf
    if print_pdf_file is not None:
        print_pdf_file.unlink(missing_ok=True)

    return None


def wait_for_page_loaded(browser: WebDriver):
    ready_state = browser.execute_script("return document.readyState")
    while str.lower(ready_state) != "complete":
        ready_state = browser.execute_script("return document.readyState")
        if str.lower(ready_state) != "complete":
            logger.info("waiting for page to load")
            time.sleep(1)
        else:
            break


def screenshot_page(url: str):
    s3_client = get_aws_client("s3")
    s3_website_Url = ""
    screenshot_url = ""

    # validate
    if not validate_url(url):
        raise ValueError("url is invalid")

    # Make sure bucket has S3 Website feature enabled
    s3_website_exists, s3_website_Url = get_s3_website_Url(bucket=AWS_S3_BUCKET_NAME)
    # Make sure bucket has S3 Website feature enabled
    s3_website_exists, s3_website_Url = get_s3_website_Url(bucket=AWS_S3_BUCKET_NAME)
    if not s3_website_exists:
        logger.critical(
            f"s3 website for '{AWS_S3_BUCKET_NAME}' does not exist. You may need to enable this."
        )

    # take screenshot
    logger.info(f"navigating to url: {url}")
    browser = new_ff_browser()
    browser.get(url)
    time.sleep(3)

    screenshot_data = get_ff_screenshot_data_png(browser=browser, width=640, height=400)

    # s3 setup
    file_basename = str.lower(format_filename(browser.title))
    short_hash = short_str(url)
    base_key = "s"
    screenshot_filekey = f"{base_key}/{file_basename}_{short_hash}.png"
    screenshot_url = f"{s3_website_Url}/{screenshot_filekey}"

    s3_client.put_object(Bucket=AWS_S3_BUCKET_NAME, Key=f"{base_key}/")

    # upload
    tmp_dir = None
    try:
        tmp_dir = tempfile.TemporaryDirectory()

        tmp_screenshot_file = pathlib.Path(tmp_dir.name).joinpath("tmp.png")
        tmp_screenshot_file.write_bytes(screenshot_data)
        logger.debug(f"uploading screenshot: {screenshot_filekey}")
        s3_client.upload_file(
            str(tmp_screenshot_file),
            AWS_S3_BUCKET_NAME,
            screenshot_filekey,
            ExtraArgs={"ContentType": "image/png"},
        )
    except:
        raise
    finally:
        if tmp_dir is not None:
            tmp_dir.cleanup()

    return screenshot_url


@logger.catch
def pull_gtasks_job(list_name: str):
    gt = get_gtask()
    scrape_list = gt.get_list(list_name)
    logger.debug(f"{len(scrape_list.tasks)}")
    for task in scrape_list.tasks:
        # assume task title is a url
        ts = datetime.now().isoformat()
        task_title = str.strip(task["title"])
        logger.info(f"task title: {task_title}")
        url = str.strip(task_title)

        # scrape valid URLs
        is_url = validate_url(url)
        if is_url:
            scraped = False
            logger.info(f"attempting to scrape url: {url}")
            _ = scrape_url(
                url=url, print_article=False, print_html=False, push_pocket=True
            )
            scraped = True
        else:
            logger.info("task title is not a url")

        # mark complete
        if scraped or not is_url:
            logger.info("marking task complete")
            scrape_list.mark_task_complete(task)


######################################
# slack event handlers
######################################
def slack_event_message(body, say, client: WebClient):
    e = dict(body["event"])
    text = str.strip(e.get("text", ""))
    if len(text) == 0:
        return

    # process message
    if text.startswith("<") or text.startswith("http"):
        # URLs
        url = str.strip(text, "<>").split("|")[0]
        ret_url = ""

        if validate_url(url):
            logger.info(f"marking message with URL for procdessing: {url}")

            # mark as processing
            client.reactions_add(
                channel=e["channel"], name="thinking_face", timestamp=e["ts"]
            )

            # scrape url
            try:
                ret_url = scrape_url(
                    url=url,
                    print_article=False,
                    print_html=False,
                    push_pocket=True,
                    retries=3,
                )
            except:
                logger.exception(f"ex parsing url {url}")

            # response
            client.reactions_remove(
                channel=e["channel"], name="thinking_face", timestamp=e["ts"]
            )

            if ret_url is None or len(ret_url) == 0:
                client.reactions_add(
                    channel=e["channel"], name="no_entry", timestamp=e["ts"]
                )
            else:
                client.reactions_add(
                    channel=e["channel"], name="white_check_mark", timestamp=e["ts"]
                )
                say(f"{ret_url}")
    else:
        logger.debug(f"ignoring msg: {text}")


######################################
# commands
######################################
CONTEXT_SETTINGS = dict(help_option_names=["-h", "--help"])

# ------------------------------------
# cli
# ------------------------------------
@click.group(
    context_settings=CONTEXT_SETTINGS,
    help="utils to help scrape and push content to pocket via s3 websites",
)
@click.version_option(version="1.0.0")
def main():
    pass


# ------------------------------------
# diag commands
# ------------------------------------
@main.group(context_settings=CONTEXT_SETTINGS, help="testing commands")
def diag():
    pass


# test-creds
@diag.command(name="test-creds", help="test API configurations")
@click.option("--test-s3/--no-test-s3", default=True, show_default=True)
@click.option("--test-gtask/--no-test-gtask", default=True, show_default=True)
@click.option("--test-pocket/--no-test-pocket", default=True, show_default=True)
@click.option("--enable-logs", is_flag=True, help="enable logs")
def cmd_test_creds(
    test_s3: bool, test_gtask: bool, test_pocket: bool, enable_logs: bool
):
    if not enable_logs:
        logger.remove()
    try:
        test_creds(test_s3=test_s3, test_gtask=test_gtask, test_pocket=test_pocket)
    except:
        logger.exception("Test Ex:")
        sys.exit(1)


@diag.command(name="save-about-support", help="save contents of about:support")
def cmd_about_support():
    browser = None
    try:
        browser = new_ff_browser()
        browser.get("about:support")
        save_file = pathlib.Path(__file__).parent.joinpath("about_support.html")
        logger.info(f"saving {save_file}")
        save_file.write_text(browser.page_source)
    finally:
        if browser is not None:
            browser.quit()


# ------------------------------------
# screenshot
# ------------------------------------
@main.group(context_settings=CONTEXT_SETTINGS, help="capture screenshots")
def screenshot():
    pass


@screenshot.command(name="url", help="screenshot a url")
@click.argument("url")
def cmd_screenshot_url(url: str):
    screenshot_url = screenshot_page(url)
    logger.info(f"url: {screenshot_url}")


# ------------------------------------
# scrape commands
# ------------------------------------
@main.group(
    context_settings=CONTEXT_SETTINGS, help="selenium firefox driven content scraping"
)
def scrape():
    pass


# scrape url
@scrape.command(name="url", help="scrape a url")
@click.argument("url")
@click.option(
    "-p",
    "--push-pocket",
    is_flag=True,
    help="push to s3 and then to pocket. requires aws files to already be configured (eg aws configure)",
)
@click.option("--retries", type=int, default=3, help="number of retries")
@click.option("--print-article/--no-print-article", default=True, show_default=True)
@click.option("--print-html/--no-print-html", default=False, show_default=True)
def cmd_scrape_url(
    url: str, print_article: bool, print_html: bool, push_pocket: bool, retries: int
):
    try:
        _ = scrape_url(
            url=url,
            print_article=print_article,
            print_html=print_html,
            push_pocket=push_pocket,
            retries=retries,
        )
    except:
        logger.exception("scrape_url ex")
        sys.exit(1)


# scrape slackbot
@scrape.command(name="slackbot", help="scrape urls from slack messages")
def cmd_scrape_slackbot():
    # app
    try:
        logger.info("connecting to slack")
        slack_app = get_slack_app()

        # events
        logger.info("registering events")
        slack_app.event("message")(slack_event_message)
    except:
        logger.exception("slackbot init ex")
        sys.exit(1)

    # websocket handler
    try:
        logger.info("starting websocket handler")
        slack_handler = SlackSocketModeHandler(app=slack_app, app_token=SLACK_APP_TOKEN)
        slack_handler.start()
    except KeyboardInterrupt:
        logger.info("goodbye")
        sys.exit(0)
    except:
        logger.exception("slackbot ex")
        sys.exit(2)


# scrape gtask-pull
@scrape.command(name="gtask-pull", help="scrape urls from google tasks")
@click.argument("list-name")
@click.option("-as", "--as-schedule", is_flag=True, help="whether to run as a schedule")
@click.option(
    "--every-secs", type=int, default=10, help="How often (secs) to run schedule"
)
def cmd_scrape_gtask_pull(list_name: str, as_schedule: bool, every_secs: int):
    if as_schedule:
        # create schedule(s)
        logger.info(f"gtask pull list '{list_name}' running every {every_secs} seconds")
        schedule.every(every_secs).seconds.do(pull_gtasks_job, list_name=list_name)

        # execution loop
        ts = datetime.now().isoformat()
        logger.info("entering scheduling loop")
        while True:
            schedule.run_pending()
            time.sleep(1)
    else:
        # run once
        pull_gtasks_job(list_name=list_name)


# ------------------------------------
# pocket commands
# ------------------------------------
@main.group(context_settings=CONTEXT_SETTINGS, help="pocket api wrapper")
def pocket():
    pass


# pocket gen-access-token
@pocket.command(
    name="gen-access-token",
    help="link a consumer key to your account via an access token. see: https://getpocket.com/developer/docs/authentication",
)
@click.option(
    "--pocket-consumer-key",
    type=str,
    envvar="READCLI_POCKET_CONSUMER_KEY",
    help="Your consumer key as generated at http://getpocket.com/developer/apps/new. Defaults to READCLI_POCKET_CONSUMER_KEY",
)
@click.option("--enable-logs", is_flag=True, help="enable logs")
def cmd_pocket_gen_access_token(pocket_consumer_key: str, enable_logs: bool):
    if not enable_logs:
        logger.remove()
    create_pocket_access_token(pocket_consumer_key)


######################################
# main
######################################
if __name__ == "__main__":
    main()
