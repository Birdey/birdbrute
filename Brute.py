"""
------------------------ Brute.py --------------------------
A domain brute force attack tool.
This tool will try to find subdomains and files on a given domain.
It will do this by brute forcing the domain with different paths and file extensions.

------------------------------------------------------------
Version: 0.1
Author: Christoffer von Matérn

Collaborators:
Christoffer von Matérn - @Birdey
Figg Eriksson
------------------------------------------------------------
MIT License
Copyright 2023 Christoffer von Matérn

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
------------------------------------------------------------
"""


from hashlib import md5
from os import cpu_count
import os
import sys
import threading
from time import sleep
import time
import requests


class TColours:
    """
    Terminal Colours.
    """

    HEADER = "\033[95m"
    OKBLUE = "\033[94m"
    OKCYAN = "\033[96m"
    OKGREEN = "\033[92m"
    WARNING = "\033[93m"
    FAIL = "\033[91m"
    ENDC = "\033[0m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"


DOMAIN_TO_VIOLATE: str
# get arguments
if len(sys.argv) > 1:
    if sys.argv[1] == "--help" or sys.argv[1] == "-h":
        print("Usage: python3 brute.py [domain]")
        print("Example: python3 brute.py https://www.speletshus.se")
        exit()
    elif sys.argv[1] == "--version" or sys.argv[1] == "-v":
        print("Version: 0.1")
        exit()
    else:
        DOMAIN_TO_VIOLATE = sys.argv[1]
        # print(f"Domain to violate: {DOMAIN_TO_VIOLATE}")
else:
    DOMAIN_TO_VIOLATE = "https://www.speletshus.se"
    # print(f"Domain to violate: {DOMAIN_TO_VIOLATE}")
    # sleep(1)


# get number of threads of the system
_processor_threads = cpu_count() * 2 - 4
MAX_THREADS = _processor_threads if _processor_threads > 4 else 4
print(f"Max threads: {MAX_THREADS}")

if "http" not in DOMAIN_TO_VIOLATE:
    DOMAIN_TO_VIOLATE = "https://" + DOMAIN_TO_VIOLATE

# print(f"Domain to violate: {DOMAIN_TO_VIOLATE}")

BAD_PAGE_SIZES = []

A_BAD_PAGE = md5(
    ("THIS_SHOULD_NOT_BE_A_VALID_PAGE" + str(time.localtime())).encode("utf-8")
).hexdigest()

LIST_OF_SUB_PATHS_AND_FILES = []
NUMBER_OF_STRINGS_TESTED = 0

FOUND_SUBDOMAINS = []
FOUND_FILES = []

FOUND_VALID_PATHS = []
FOUND_FORBIDDEN_PATHS = []
FOUND_UNAUTHORIZED_PATHS = []
FOUND_BAD_REQUEST_PATHS = []

FILE_EXT = [".php", ".html"]

FILE_EXT_LONG = [
    ".php",
    ".html",
    ".jsp",
    ".js",
    ".txt",
    ".pdf",
    ".doc",
    ".docx",
    ".xls",
    ".xlsx",
    ".csv",
    ".json",
    ".zip",
    ".rar",
    ".tar",
    ".gzip",
    ".gz",
    ".mp3",
    ".mp4",
    ".avi",
    ".mov",
    ".jpg",
    ".jpeg",
    ".png",
    ".gif",
    ".xml",
]

BRUTE_FORCING: bool = False


def brute_async():
    """
    Run brute forcing async.
    """
    global BRUTE_FORCING

    if BRUTE_FORCING:
        return

    BRUTE_FORCING = True

    while len(LIST_OF_SUB_PATHS_AND_FILES) > 0:
        path = LIST_OF_SUB_PATHS_AND_FILES.pop(0)

        path_to_violate = f"{DOMAIN_TO_VIOLATE}/{path}"
        thread_name = f"Brute {path_to_violate}"

        start_thread(brute_domain, thread_name, path_to_violate)

        # for ext in list_of_file_extensions:
        #     path_to_violate = f"{domain_to_violate}/{path}{ext}"
        #     thread_name = f"Brute {path_to_violate}"
        #     startThread(brute_domain, thread_name, path_to_violate)

    BRUTE_FORCING = False


def start_thread(target, name: str, args: str):
    """
    Start a thread and wait if the number of threads is more than the max.

    Parameters
    ----------
    target : function
        The function to run in the thread.
    name : str
        The name of the thread.
    args : str
        The arguments to pass to the function.
    """
    while threading.active_count() > MAX_THREADS:
        sleep(0.01)
    threading.Thread(target=target, name=name, args=(args,)).start()

    global NUMBER_OF_STRINGS_TESTED
    NUMBER_OF_STRINGS_TESTED += 1


def brute_domain(string: str):
    """
    Brute force a single domain.

    Parameters
    ----------
    string : str
        The url to brute force.
    """

    status_code, size = ping_url(string)

    if status_code == 0:
        # print(f"Ignoring page {test_url}")
        return
    if status_code == 200 or status_code == 301 or status_code == 302:
        # If the status code is 200, 301, 302 or 404, then add it to a list.
        print(f"{TColours.OKGREEN}Avilable page: {string}\033[J")
        FOUND_VALID_PATHS.append(string)
        add_to_subdomains_or_files(string)

    elif status_code == 404:
        # If the status code is 404, then add it to a list of not found pages.
        # print(f"Page not found: {test_url}")
        pass

    elif status_code == 400:
        # If the status code is 400, then add it to a list of bad requests.
        print(f"{TColours.FAIL}Bad request: {string}\033[J")
        # add_to_subdomains_or_files(string)

        FOUND_BAD_REQUEST_PATHS.append(string)

    elif status_code == 401:
        # If the status code is 401, then add it to a list of unauthorized pages.
        print(f"{TColours.WARNING}Unauthorized page: {string}\033[J")
        FOUND_UNAUTHORIZED_PATHS.append(string)

    elif status_code == 403:
        # If the status code is 403, then add it to a list of forbidden pages.
        print(f"{TColours.FAIL}Forbidden page: {string}\033[J")
        FOUND_FORBIDDEN_PATHS.append(string)
        add_to_subdomains_or_files(string)

    elif status_code == 500:
        # If the status code is 500, then add it to a list of internal server error pages.
        # print(f"{bcolors.WARNING}Internal server error page: {string}\033[J")
        add_to_list(string.split("/")[-1])


def add_to_subdomains_or_files(string: str):
    """
    Add a string to a list of subdomains or files.

    Parameters
    ----------
    string : str
        The url to add to a list.
    """
    last_part = string.split("/")[-1]
    if "." in last_part:
        # if string is a file then add it to a list of files.
        FOUND_FILES.append(string)
    else:
        # if string is a subdomain then add it to a list of subdomains.
        FOUND_SUBDOMAINS.append(string)


def ping_url(url: str) -> tuple[int, int]:
    """
    Ping a url and return the status code.

    Parameters
    ----------
    url : str
        The url to ping.

    Returns
    -------
    tuple[int, int]
        The status code and the size of the page.

    Examples
    --------
    >>> ping_url("http://www.speletshus.se")
    200, 3943
    >>> ping_url("http://www.speletshus.se/this_page_should_not_exist")
    404, None
    """

    try:
        request = requests.get(url=url, timeout=5)
        size = len(request.content)

        if size in BAD_PAGE_SIZES:
            return 404, size
        else:
            return request.status_code, size
    except requests.exceptions.SSLError:
        pass
    except requests.ConnectionError:
        pass
    except requests.exceptions.ReadTimeout:
        pass
    return 404, 0


def shorten_number(number: int):
    """
    Shorten a number to a string with 3 digits.
    """
    suffix = ""
    if number > 1000000000000:
        number = number / 1000000000000
        suffix = "T"
    elif number > 1000000000:
        number = number / 1000000000
        suffix = "B"
    elif number > 1000000:
        number = number / 1000000
        suffix = "M"
    elif number > 1000:
        number = number / 1000
        suffix = "K"

    number = round(number, 1)
    return f"{number}{suffix}"


def add_to_list(string: str):
    """
    Add a string to a list if it does not already exist in the list.

    Parameters
    ----------
    string : str
        The string to add to a list.
    """
    global LIST_OF_SUB_PATHS_AND_FILES
    if string not in LIST_OF_SUB_PATHS_AND_FILES:
        LIST_OF_SUB_PATHS_AND_FILES.append(string)


def get_a_list_of_strings(quick_run: bool = False):
    """
    Get a list of strings.

    Parameters
    ----------
    short_run : bool, optional
        If the list should be a short list or not. The default is False.

    Examples
    --------
    >>> get_a_list_of_strings()
    ["dev", "beta", "home", "index", "login", "admin", "admin.php", "admin.html"]
    """

    global LIST_OF_SUB_PATHS_AND_FILES
    LIST_OF_SUB_PATHS_AND_FILES = []
    add_to_list("THIS_SHOULD_NOT_BE_A_VALID_PAGE")

    # load lines from file into string_list
    file_data: list
    with open("words.txt", "r") as file:
        file_data = file.readlines()
        file_data = [x.replace("\n", "") for x in file_data]
        file.close()

    total_lines = len(file_data) * len(FILE_EXT) + len(file_data)
    current_line = 0

    global NUMBER_OF_STRINGS_TESTED
    NUMBER_OF_STRINGS_TESTED = 0

    for line in file_data:
        line = line.strip()
        if not line:
            continue

        add_to_list(line)
        current_line += 1

        if not quick_run:
            for ext in FILE_EXT if quick_run else FILE_EXT_LONG:
                add_to_list(line + ext)

            # Print a progress bar
            if current_line % 100 == 0:
                get_percent = round((current_line / total_lines) * 100, 2)
                str_tested = shorten_number(current_line)
                str_left = shorten_number(total_lines - current_line)
                print(
                    f"Loading strings: added {str_tested} with {str_left} left to add | {get_percent}%\033[J",
                    end="\r",
                )

        if quick_run and current_line > 1000:
            break

    # for line in file_data:
    #     if line.rstrip() == "":
    #         continue

    #     add_to_list(line.rstrip())
    #     current_line += 1
    #     if quick_run:
    #         # if current_line == 1000:
    #         #     break
    #         pass
    #     else:
    #         for ext in FILE_EXT:
    #             add_to_list(line.rstrip() + ext)
    #             # Print a progress bar
    #             current_line += 1
    #             if current_line % 100 == 0:
    #                 get_percent = round((current_line / total_lines) * 100, 2)
    #                 str_tested = shorten_number(current_line)
    #                 str_left = shorten_number(total_lines - current_line)
    #                 print(
    #                     f"Loading strings: added {str_tested} with {str_left} left to add | {get_percent}%\033[J",
    #                     end="\r",
    #                 )


def brute():
    """
    Brute force attack on a website to find subdomains and files on the server.
    """
    # clear screen
    print("\033c", end="")
    # print("Brute forcing. Please wait...")
    # print("")

    get_a_list_of_strings(quick_run=False)
    brute_async()

    return


def print_header():
    # clear screen
    print("\033c", end="")
    print(f"{TColours.HEADER}#" * 50)
    print(f"{TColours.HEADER}#" * 50)
    print(f'{TColours.HEADER}{"#" * 2}{" " * 46}{"#" * 2}')
    print(f"{TColours.HEADER}## Brute.py by Christoffer von Matérn - @Birdey ##")
    print(f'{TColours.HEADER}{"#" * 2}{" " * 46}{"#" * 2}')
    print(f"{TColours.HEADER}#" * 50)
    print(f"{TColours.HEADER}#" * 50)
    print(f"{TColours.OKCYAN}Domain to violate: {DOMAIN_TO_VIOLATE}")
    print(f"{TColours.OKCYAN}Max threads: {MAX_THREADS}")
    if len(BAD_PAGE_SIZES) > 0:
        print(f"{TColours.OKCYAN}Bad page sizes: {BAD_PAGE_SIZES}")
    print(f"{TColours.HEADER}#" * 50)
    print("")
    return


def test_bad_url():
    """
    Test a bad url.
    """
    test_url = f"{DOMAIN_TO_VIOLATE}/{A_BAD_PAGE}"
    status_code, size = ping_url(test_url)
    if status_code != 404:
        print(f"{TColours.FAIL}Bad url: {test_url} is not returning 404\033[J")
        BAD_PAGE_SIZES.append(size)


def brute2(all_file_extensions: bool = False, test_run: bool = False):
    """
    Brute force attack on a website to find subdomains and files on the server.

    Parameters
    ----------
    all_file_extensions : bool, optional
        Should all file extensions be tested or not. The default is False.
    """

    test_bad_url()
    print_header()

    testing_strings: list[str]
    if test_run:
        # load short list of strings into string_list
        testing_strings = [
            "res",
            "images",
            "img",
            "css",
            "js",
            "fonts",
            "lib",
            "src",
            "pages",
            "page",
            "home",
            "index",
            "login",
            "admin",
            "files",
            "beta",
            "dev",
            "old",
            "new",
            "backup",
            "backups",
            "backup_files",
            "test",
            "tests",
            "testing",
            "staging",
            "path",
            "paths",
            "public",
            "private",
            "user",
            "users",
            "account",
            "accounts",
            "profile",
            "profiles",
            "upload",
            "uploads",
            "download",
            "downloads",
            "media",
        ]
    else:
        # Load lines from words.txt into string_list
        list_of_test_strings = open("words.txt", "r", encoding="utf-8")
        testing_strings = list_of_test_strings.readlines()
        list_of_test_strings.close()

    update_screen_at = MAX_THREADS * 2

    # Get correct list of file extensions.
    if all_file_extensions and not test_run:
        list_of_file_extensions = FILE_EXT_LONG
    else:
        list_of_file_extensions = FILE_EXT

    # Add all file extensions to the end of the testing strings.
    _new_testing_strings = []

    for index, _string in enumerate(testing_strings):
        if _string.strip() == "":
            print(f"Skipping '{_string}' at line {index}")
            sleep(10)
        _new_testing_strings.append(_string.strip())
        for file_ext in list_of_file_extensions:
            _new_testing_strings.append(f"{_string.strip()}{file_ext}")

        percent = round((index / len(testing_strings)) * 100, 2)
        print(
            f"{TColours.OKCYAN}Preparing strings: {percent}% | {_string.strip()}",
            end="\r",
        )
    testing_strings = _new_testing_strings

    # Start the brute forcing.
    for index, _string in enumerate(testing_strings):
        string = _string.strip()
        if not string:
            continue

        test_url = f"{DOMAIN_TO_VIOLATE}/{string}"

        while threading.active_count() > MAX_THREADS:
            sleep(0.01)

        start_thread(brute_domain, f"Brute {test_url}", test_url)

        if index % update_screen_at == 0:
            str_tested = shorten_number(index)
            str_left = shorten_number(len(testing_strings) - index)
            percent = round((index / len(testing_strings)) * 100, 2)
            print(
                f"{TColours.OKCYAN}Testing: {str_tested} with {str_left} left | {percent}% | {string}\033[J",
                end="\r",
            )


def save_data():
    """
    Save the data to a file.
    """
    # create a path folder from the domain
    save_path = DOMAIN_TO_VIOLATE
    print(f"Saving data to {save_path}")
    save_path = save_path.replace("https://", "")
    print(f"Saving data to {save_path}")
    save_path = save_path.replace("http://", "")
    print(f"Saving data to {save_path}")
    save_path = save_path.replace("www.", "")
    print(f"Saving data to {save_path}")
    save_path = save_path.replace(".", "_")
    print(f"Saving data to {save_path}")
    save_path = f"results/{save_path}"

    if not os.path.exists(save_path):
        os.makedirs(save_path)

    file_name = "bruteforce_" + time.strftime("%Y-%m-%d")

    with open(file=f"{save_path}/{file_name}.txt", mode="w", encoding="utf-8") as file:
        # if len(FOUND_VALID_PATHS) != 0:
        #     file.write("Valid paths:\n")
        #     for path in FOUND_VALID_PATHS:
        #         file.write(path + "\n")

        if len(FOUND_SUBDOMAINS) != 0:
            file.write("\nSub domains:\n")
            for sub_domain in FOUND_SUBDOMAINS:
                file.write(sub_domain + "\n")

        if len(FOUND_FILES) != 0:
            file.write("\nFiles:\n")
            for file_path in FOUND_FILES:
                file.write(file_path + "\n")

        if len(FOUND_BAD_REQUEST_PATHS) != 0:
            file.write("\nBad request pages:\n")
            for bad_request in FOUND_BAD_REQUEST_PATHS:
                file.write(bad_request + "\n")

        if len(FOUND_FORBIDDEN_PATHS) != 0:
            file.write("\nForbidden pages:\n")
            for forbidden_page in FOUND_FORBIDDEN_PATHS:
                file.write(forbidden_page + "\n")

        if len(FOUND_UNAUTHORIZED_PATHS) != 0:
            file.write("\nUnauthorized pages:\n")
            for unauthorized_page in FOUND_UNAUTHORIZED_PATHS:
                file.write(unauthorized_page + "\n")

        file.close()

    print(f"{TColours.OKGREEN}Saved data to {save_path}/{file_name}.txt")


def slugify(value: str):
    """
    Slugify a string.
    """
    return (
        value.lower()
        .replace(" ", "-")
        .replace("/", "-")
        .replace(".", "-")
        .replace(":", "-")
    )


def main():
    """
    Main function for the program.
    """
    # Run the brute force attack.
    brute2(all_file_extensions=False, test_run=False)

    # Wait for threads to finish
    while threading.active_count() > 1:
        # clear screen
        sleep(0.1)
        print(f"Active threads: {threading.active_count()}", end="\r")
    print("")

    save_data()

    # Print the results of the brute force attack.
    print(f"{TColours.HEADER}#" * 10)
    print_list(FOUND_SUBDOMAINS, "Sub Domains", 10)
    print_list(FOUND_FILES, "List of files", 10)
    print_list(FOUND_FORBIDDEN_PATHS, "Forbidden pages", 10)
    print_list(FOUND_BAD_REQUEST_PATHS, "Bad request pages", 10)
    print_list(FOUND_UNAUTHORIZED_PATHS, "Unauthorized pages", 10)
    print(f"{TColours.HEADER}#" * 10)

    return


def print_list(
    list_to_print: list, title: str = "List", max_to_print: int = float("inf")
):
    """
    Print a list of strings.
    """
    if len(list_to_print) == 0:
        return

    # Print a header
    print(f"{TColours.HEADER}=" * len(title) * 2)
    print(f"{TColours.HEADER}{title}:")
    print(f"{TColours.HEADER}-" * len(title) * 2)
    # Print the paths
    current_printed = 0
    for path in list_to_print:
        print(f"{TColours.OKGREEN}{path}")
        current_printed += 1
        if current_printed >= max_to_print:
            print(f"{TColours.OKCYAN}+{len(list_to_print)-current_printed} more...")
            break

    # Print a footer
    print(f"{TColours.HEADER}=" * len(title) * 2)
    print("")


if __name__ == "__main__":
    print("-- Brute.py --")

    main()

    # input(f"{TColours.OKBLUE}Press enter to see Subdomains")
    # print_list(FOUND_SUBDOMAINS, "Sub Domains")
    # input(f"{TColours.OKBLUE}Press enter to see files")
    # print_list(FOUND_FILES, "List of files")
    # input(f"{TColours.OKBLUE}Press enter to see forbidden pages")
    # print_list(FOUND_FORBIDDEN_PATHS, "Forbidden pages")
    # input(f"{TColours.OKBLUE}Press enter to see bad request pages")
    # print_list(FOUND_BAD_REQUEST_PATHS, "Bad request pages")
    # input(f"{TColours.OKBLUE}Press enter to see unauthorized pages")
    # print_list(FOUND_UNAUTHORIZED_PATHS, "Unauthorized pages")
    # input(f"{TColours.OKBLUE}Press enter to Exit the program")

    print("-- end --")
    print("--------------")
